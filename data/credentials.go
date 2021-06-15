package data

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/fakhripraya/authentication-service/config"
	"github.com/fakhripraya/authentication-service/database"
	"github.com/fakhripraya/authentication-service/mailer"
	protos "github.com/fakhripraya/emailing-service/protos/email"
	waProtos "github.com/fakhripraya/whatsapp-service/protos/whatsapp"
	"golang.org/x/oauth2"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/go-hclog"
	"github.com/srinathgs/mysqlstore"
)

// Claims determine the token holder
type Claims struct {
	Username string
	jwt.StandardClaims
}

// Credentials defines a struct for credentials flow
type Credentials struct {
	waClient          waProtos.WhatsAppClient
	emailClient       protos.EmailClient
	emailHandler      *mailer.Email
	logger            hclog.Logger
	googleOauthConfig *oauth2.Config
	oauthStateString  string
}

// NewCredentials is a function to create new credentials struct
func NewCredentials(waClient waProtos.WhatsAppClient, emailClient protos.EmailClient, emailHandler *mailer.Email, newLogger hclog.Logger, newGoogleOauthConfig *oauth2.Config, newOauthStateString string) *Credentials {
	return &Credentials{waClient, emailClient, emailHandler, newLogger, newGoogleOauthConfig, newOauthStateString}
}

// GetGoogleUserInfo process the google OAuth2 user info
func (cred *Credentials) GetGoogleUserInfo(state string, code string) ([]byte, error) {
	if state != cred.oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := cred.googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	return contents, nil
}

// GetCurrentUser will get the current user login info
func (cred *Credentials) GetCurrentUser(rw http.ResponseWriter, r *http.Request, store *mysqlstore.MySQLStore) (*database.MasterUser, error) {

	// Get a session (existing/new)
	session, err := store.Get(r, "session-name")
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)

		return nil, err
	}

	// check the logged in user from the session
	// if user available, get the user info from the session
	if session.Values["userLoggedin"] == nil {
		rw.WriteHeader(http.StatusUnauthorized)

		return nil, fmt.Errorf("Error 401")
	}

	// work with database
	// look for the current user logged in in the db
	var currentUser database.MasterUser
	if err := config.DB.Where("username = ?", session.Values["userLoggedin"].(string)).First(&currentUser).Error; err != nil {
		rw.WriteHeader(http.StatusBadRequest)

		return nil, err
	}

	return &currentUser, nil

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
func (cred *Credentials) GenerateOTP() (string, error) {

	var max int = 4
	var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		return "", err
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}

	// returns the crypted otp number
	return string(b), nil

}

// SendOTP is a function to send OTP to either users email or phone number (WA)
func (cred *Credentials) SendOTP(rw http.ResponseWriter, r *http.Request, user *database.MasterUser, store *mysqlstore.MySQLStore) (string, error) {
	// generate OTP
	newOTP, err := cred.GenerateOTP()

	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return "", err
	}

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
			if resp.ErrorCode != "200" {
				if resp.ErrorCode == "404" {
					rw.WriteHeader(http.StatusNotFound)
				}
				if resp.ErrorCode == "500" {
					rw.WriteHeader(http.StatusInternalServerError)
				}

				return "", fmt.Errorf(resp.ErrorMessage)
			}

			return "OTP Code has been sent to your email", nil
		}
	} else if mailer.IsWhatsAppValid(user.Username) {
		// if with phone (WA)

		// send WhatsApp through gRPC service
		war := &waProtos.WARequest{
			RemoteJid: user.Username + "@s.whatsapp.net",
			Text:      "kode verifikasi akun Indekos anda adalah " + newOTP,
		}

		waResp, _ := cred.waClient.SendWhatsApp(context.Background(), war)

		if waResp != nil {
			if waResp.ErrorCode != "200" {
				if waResp.ErrorCode == "400" {
					rw.WriteHeader(http.StatusBadRequest)
				}
				if waResp.ErrorCode == "404" {
					rw.WriteHeader(http.StatusNotFound)
				}
				if waResp.ErrorCode == "500" {
					rw.WriteHeader(http.StatusInternalServerError)
				}

				return "", fmt.Errorf(waResp.ErrorMessage)
			}

			return "OTP Code has been sent to your WhatsApp", nil
		}
	} else {

		// if the username neither phone number nor email
		rw.WriteHeader(http.StatusBadRequest)
		return "", fmt.Errorf("Invalid phone number / email")
	}

	// throws internal server error if validation fails
	rw.WriteHeader(http.StatusInternalServerError)
	return "", fmt.Errorf("Something went wrong, please try to use either email or phone number instead")
}
