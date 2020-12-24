package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/fakhripraya/authentication-service/config"
	"github.com/fakhripraya/authentication-service/data"
	"github.com/fakhripraya/authentication-service/entities"
	"github.com/fakhripraya/authentication-service/handlers"
	"github.com/fakhripraya/authentication-service/mailer"
	protos "github.com/fakhripraya/emailing-service/protos/email"
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

	// create a structured logger for logging the entire program
	logger := hclog.Default()

	// load configuration from env file
	err = godotenv.Load(".env")

	if err != nil {
		// log the fatal error if load env failed
		log.Fatal(err)
	}

	// Initialize app configuration
	var appConfig entities.Configuration
	data.ConfigInit(&appConfig)

	// creates a gRPC connection WithInsecure
	emailConn, err := grpc.Dial("localhost:9092", grpc.WithInsecure()) // TODO: put the address in the config
	if err != nil {
		log.Fatal(err)
	}

	defer emailConn.Close()

	// create gRPC client connection
	clientConnection := protos.NewEmailClient(emailConn)

	// Open the database connection based on DB configuration
	logger.Info("Establishing database connection on DB : " + appConfig.Database.Host + ":" + strconv.Itoa(appConfig.Database.Port))
	config.DB, err = gorm.Open("mysql", config.DbURL(config.BuildDBConfig(&appConfig.Database)))
	if err != nil {
		logger.Error("Error while establishing database connection", "error", err.Error())
		log.Fatal(err)
	}
	defer config.DB.Close()

	// Migrate all the defined table into the database
	data.MigrateDB(config.DB)

	// Create a session store based on MYSQL database
	// If table doesn't exist, creates a new one
	logger.Info("Building session store based on DB : " + appConfig.Database.Host + ":" + strconv.Itoa(appConfig.Database.Port))
	sessionStore, err = mysqlstore.NewMySQLStore(config.DbURL(config.BuildDBConfig(&appConfig.Database)), "dbMasterSession", "/", 3600*24*7, []byte(appConfig.MySQLStore.Secret))
	if err != nil {
		logger.Error("Error while building application session store", "error", err.Error())
		log.Fatal(err)
	}

	defer sessionStore.Close()

	// create a whatsapp login / fetch current session
	waSender, err := mailer.NewWA(logger)
	if err != nil {
		logger.Error("Error while establishing WhatsApp connection", "error", err.Error())
		log.Fatal(err)
	}

	// create an email smtp protocol
	emailSender := mailer.NewEmail(logger)

	// create a credentials instance
	credentials := data.NewCredentials(clientConnection, logger)

	// create the handlers
	authHandler := handlers.NewAuth(logger, credentials, sessionStore, emailSender, waSender)

	// create a new serve mux
	serveMux := mux.NewRouter()

	// handlers for the API
	getRequest := serveMux.Methods(http.MethodGet).Subrouter()
	getRequest.HandleFunc("/", authHandler.GetInfo)
	getRequest.Use(authHandler.MiddlewareValidateAuth)

	postRequest := serveMux.Methods(http.MethodPost).Subrouter()
	postRequest.HandleFunc("/login", authHandler.Login)
	postRequest.HandleFunc("/register", authHandler.Register)
	postRequest.HandleFunc("/register/check", Adapt(
		http.HandlerFunc(authHandler.RegisterFinal),
		authHandler.MiddlewareCheckOTP,
	).ServeHTTP)
	postRequest.HandleFunc("/login/check", Adapt(
		http.HandlerFunc(authHandler.LoginFinal),
		authHandler.MiddlewareCheckOTP,
	).ServeHTTP)
	postRequest.Use(authHandler.MiddlewareParseCredentialsRequest)

	// CORS
	corsHandler := gohandlers.CORS(gohandlers.AllowedOrigins([]string{"*"}))

	// create a new server
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
		logger.Info("Starting server on port " + strconv.Itoa(appConfig.API.Port))

		err = server.ListenAndServe()
		if err != nil {
			logger.Error("Error starting server", "error", err.Error())
			os.Exit(1)
		}
	}()

	// trap sigterm or interrupt and gracefully shutdown the server
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)
	signal.Notify(channel, os.Kill)

	// Block until a signal is received.
	sig := <-channel
	log.Println("Got signal:", sig)

	// gracefully shutdown the server, waiting max 30 seconds for current operations to complete
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	server.Shutdown(ctx)
}
