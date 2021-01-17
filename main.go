package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/fakhripraya/authentication-service/config"
	"github.com/fakhripraya/authentication-service/data"
	"github.com/fakhripraya/authentication-service/entities"
	"github.com/fakhripraya/authentication-service/handlers"
	"github.com/fakhripraya/authentication-service/mailer"
	protos "github.com/fakhripraya/emailing-service/protos/email"
	waProtos "github.com/fakhripraya/whatsapp-service/protos/whatsapp"
	gohandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-hclog"
	"github.com/jinzhu/gorm"
	"github.com/joho/godotenv"
	"github.com/srinathgs/mysqlstore"
	"google.golang.org/grpc"
)

var err error

// Session Store based on MYSQL database
var sessionStore *mysqlstore.MySQLStore

// Adapter is an alias
type Adapter func(http.Handler) http.Handler

// Adapt takes Handler funcs and chains them to the main handler.
func Adapt(handler http.Handler, adapters ...Adapter) http.Handler {
	// The loop is reversed so the adapters/middleware gets executed in the same
	// order as provided in the array.
	for i := len(adapters); i > 0; i-- {
		handler = adapters[i-1](handler)
	}
	return handler
}

func main() {

	// creates a structured logger for logging the entire program
	logger := hclog.Default()

	// load configuration from env file
	err = godotenv.Load(".env")

	if err != nil {
		// log the fatal error if load env failed
		log.Fatal(err)
	}

	// Initialize app configuration
	var appConfig entities.Configuration
	err = data.ConfigInit(&appConfig)

	if err != nil {
		// log the fatal error if config init failed
		log.Fatal(err)
	}

	// creates an Email gRPC service connection WithInsecure
	logger.Info("Establishing Email gRPC Connection on " + appConfig.EmailgRPC.Host + ":" + appConfig.EmailgRPC.Port)
	emailConn, err := grpc.Dial(appConfig.EmailgRPC.Host+":"+appConfig.EmailgRPC.Port, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer emailConn.Close()

	// creates a WhatsApp gRPC service connection WithInsecure
	logger.Info("Establishing WhatsApp gRPC Connection on " + appConfig.WAgRPC.Host + ":" + appConfig.WAgRPC.Port)
	waConn, err := grpc.Dial(appConfig.WAgRPC.Host+":"+appConfig.WAgRPC.Port, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer waConn.Close()

	// creates an Email gRPC service client connection
	logger.Info("Creating gRPCs services client connection")
	emailConnClient := protos.NewEmailClient(emailConn)
	// creates a WhatsApp gRPC service client connection
	waConnClient := waProtos.NewWhatsAppClient(waConn)

	// Open the database connection based on DB configuration
	logger.Info("Establishing database connection on " + appConfig.Database.Host + ":" + strconv.Itoa(appConfig.Database.Port))
	config.DB, err = gorm.Open("mysql", config.DbURL(config.BuildDBConfig(&appConfig.Database)))
	if err != nil {
		log.Fatal(err)
	}

	defer config.DB.Close()

	// Creates a session store based on MYSQL database
	// If table doesn't exist, creates a new one
	logger.Info("Building session store based on " + appConfig.Database.Host + ":" + strconv.Itoa(appConfig.Database.Port))
	sessionStore, err = mysqlstore.NewMySQLStore(config.DbURL(config.BuildDBConfig(&appConfig.Database)), "dbMasterSession", "/", 3600*24*7, []byte(appConfig.MySQLStore.Secret))
	if err != nil {
		log.Fatal(err)
	}

	defer sessionStore.Close()

	// creates an email handler
	emailHandler := mailer.NewEmail(logger)

	// creates a credentials instance
	credentials := data.NewCredentials(waConnClient, emailConnClient, emailHandler, logger)

	// creates the handlers
	authHandler := handlers.NewAuthHandler(logger, credentials, sessionStore)

	// creates a new serve mux
	serveMux := mux.NewRouter()

	// handlers for the API
	logger.Info("Setting handlers for the API")

	// get handlers
	getRequest := serveMux.Methods(http.MethodGet).Subrouter()

	// get user handler
	getRequest.HandleFunc("/", authHandler.GetInfo)

	// get global middleware
	getRequest.Use(authHandler.MiddlewareValidateAuth)

	// post handlers
	postRequest := serveMux.Methods(http.MethodPost).Subrouter()

	// register post handler
	postRequest.HandleFunc("/register", authHandler.Register)
	postRequest.HandleFunc("/register/check", Adapt(
		http.HandlerFunc(authHandler.OtpValidate),
		authHandler.MiddlewareCheckOTP,
	).ServeHTTP)
	postRequest.HandleFunc("/register/create", authHandler.RegisterFinal)

	// login post handler
	postRequest.HandleFunc("/login", authHandler.Login)
	postRequest.HandleFunc("/login/check", Adapt(
		http.HandlerFunc(authHandler.LoginFinal),
		authHandler.MiddlewareCheckOTP,
	).ServeHTTP)

	// post global middleware
	postRequest.Use(authHandler.MiddlewareParseCredentialsRequest)

	// CORS
	corsHandler := gohandlers.CORS(gohandlers.AllowedOrigins([]string{"*"}))

	// creates a new server
	server := http.Server{
		Addr:         appConfig.API.Host + ":" + strconv.Itoa(appConfig.API.Port), // configure the bind address
		Handler:      corsHandler(serveMux),                                       // set the default handler
		ErrorLog:     logger.StandardLogger(&hclog.StandardLoggerOptions{}),       // set the logger for the server
		ReadTimeout:  5 * time.Second,                                             // max time to read request from the client
		WriteTimeout: 10 * time.Second,                                            // max time to write response to the client
		IdleTimeout:  120 * time.Second,                                           // max time for connections using TCP Keep-Alive
	}

	// start the server
	go func() {
		logger.Info("Starting server on port " + appConfig.API.Host + ":" + strconv.Itoa(appConfig.API.Port))

		err = server.ListenAndServe()
		if err != nil {

			if strings.Contains(err.Error(), "http: Server closed") == true {
				os.Exit(0)
			} else {
				logger.Error("Error starting server", "error", err.Error())
				os.Exit(1)
			}
		}
	}()

	// trap sigterm or interrupt and gracefully shutdown the server
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)
	signal.Notify(channel, os.Kill)

	// Block until a signal is received.
	sig := <-channel
	logger.Info("Got signal", "info", sig)

	// gracefully shutdown the server, waiting max 30 seconds for current operations to complete
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	server.Shutdown(ctx)
}
