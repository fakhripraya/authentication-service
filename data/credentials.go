package data

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/fakhripraya/authentication-service/mailer"
	"github.com/fakhripraya/authentication-service/migrate"
	protos "github.com/fakhripraya/emailing-service/protos/email"
	waProtos "github.com/fakhripraya/whatsapp-service/protos/whatsapp"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/go-hclog"
	"github.com/srinathgs/mysqlstore"
)

// Claims determine the token holder
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Credentials defines a struct for credentials flow
type Credentials struct {
	waClient     waProtos.WhatsAppClient
	emailClient  protos.EmailClient
	emailHandler *mailer.Email
	logger       hclog.Logger
}

// NewCredentials is a function to create new credentials struct
func NewCredentials(waClient waProtos.WhatsAppClient, emailClient protos.EmailClient, emailHandler *mailer.Email, newLogger hclog.Logger) *Credentials {
	return &Credentials{waClient, emailClient, emailHandler, newLogger}
}

// GenerateJWT Generates a JWT token by validating the signing key
func (cred *Credentials) GenerateJWT(rw http.ResponseWriter, r *http.Request, store *mysqlstore.MySQLStore, username string) error {

	// Set the expiration time
	expirationTime := time.Now().Add(time.Second * 86400 * 7)

	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "Indekos",
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(MySigningKey))
	if err != nil {
		return err
	}

	// Get a session (existing/new)
	session, err := store.Get(r, "session-name")
	if err != nil {
		return err
	}

	// session configuration
	session.Options.MaxAge = 86400 * 7

	// Set some session values.
	session.Values["token"] = tokenString
	// Delete the session otp value
	delete(session.Values, "otp")

	// Save it before we write to the response/return from the handler.
	err = session.Save(r, rw)
	if err != nil {
		return err
	}

	return nil
}

// GenerateOTP Generates an OTP code string
func (cred *Credentials) GenerateOTP() string {

	// Generates a random number from 0 - 999999
	cred.logger.Info("Generating OTP")
	ranNum := rand.Intn(999999-10000) + 10000

	// Convert the random number to string
	otp := strconv.Itoa(ranNum)

	return otp
}

// SendOTP is a function to send OTP to either users email or phone number (WA)
func (cred *Credentials) SendOTP(rw http.ResponseWriter, r *http.Request, user *migrate.MasterUser, store *mysqlstore.MySQLStore) (string, error) {
	// generate OTP
	newOTP := cred.GenerateOTP()

	// Get a session (existing/new)
	session, err := store.Get(r, "session-name")
	if err != nil {
		return "", err
	}

	// set the otp to the session
	session.Options.MaxAge = 86400 * 7
	session.Values["otp"] = newOTP
	err = session.Save(r, rw)

	if err != nil {
		return "", err
	}

	// validate either the username is email or phone
	if mailer.IsEmailValid(user.Username) {
		// if with email

		data := struct {
			OTP           string
			CopyrightDate string
		}{
			OTP:           newOTP,
			CopyrightDate: strconv.Itoa(time.Now().Year()),
		}

		// parse an email template
		template, err := cred.emailHandler.ParseTemplate("/mailer/OTPVerification.html", data)
		if err != nil {
			return "", err
		}

		// send email through gRPC service
		er := &protos.EmailRequest{
			To:      []string{user.Username},
			Cc:      []string{},
			Subject: "Verifikasi akun Indekos anda",
			Body:    template,
		}

		resp, _ := cred.emailClient.SendEmail(context.Background(), er)

		if resp != nil {
			if resp.ErrorCode == "404" {
				rw.WriteHeader(http.StatusNotFound)
			}
			if resp.ErrorCode == "500" {
				rw.WriteHeader(http.StatusInternalServerError)
			}

			return "", fmt.Errorf(resp.ErrorMessage)
		}

	} else {
		// if with phone (WA)

		// send WhatsApp through gRPC service
		war := &waProtos.WARequest{
			RemoteJid: user.Username + "@s.whatsapp.net",
			Text:      "kode verifikasi akun Indekos anda adalah " + newOTP,
		}

		waResp, _ := cred.waClient.SendWhatsApp(context.Background(), war)

		if waResp != nil {
			if waResp.ErrorCode == "404" {
				rw.WriteHeader(http.StatusNotFound)
			}

			return "", fmt.Errorf(waResp.ErrorMessage)
		}

		return "OTP Code has been sent to your whatsapp", nil
	}
	return "OTP Code has been sent to your email", nil
}
