package data

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	mathRand "math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/fakhripraya/authentication-service/config"
	"github.com/fakhripraya/authentication-service/database"
	"github.com/fakhripraya/authentication-service/mailer"
	protos "github.com/fakhripraya/emailing-service/protos/email"
	waProtos "github.com/fakhripraya/whatsapp-service/protos/whatsapp"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
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
	waClient            waProtos.WhatsAppClient
	emailClient         protos.EmailClient
	emailHandler        *mailer.Email
	logger              hclog.Logger
	googleOauthConfig   *oauth2.Config
	facebookOauthConfig *oauth2.Config
	oauthStateString    string
}

// NewCredentials is a function to create new credentials struct
func NewCredentials(waClient waProtos.WhatsAppClient, emailClient protos.EmailClient, emailHandler *mailer.Email, newLogger hclog.Logger, newGoogleOauthConfig *oauth2.Config, newFacebookOauthConfig *oauth2.Config, newOauthStateString string) *Credentials {
	return &Credentials{waClient, emailClient, emailHandler, newLogger, newGoogleOauthConfig, newFacebookOauthConfig, newOauthStateString}
}

// GetFacebookUserInfo process the facebook OAuth2 user info
func (cred *Credentials) GetFacebookUserInfo(state, code string) ([]byte, error) {
	if state != cred.oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := cred.facebookOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://graph.facebook.com/me?fields=id,name,email,location,age_range,gender&access_token=" + token.AccessToken)
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

// GetGoogleUserInfo process the google OAuth2 user info
func (cred *Credentials) GetGoogleUserInfo(state, code string) ([]byte, error) {
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

// CreateO2AuthUser is a function to create O2Auth user based on the given login provider
func (cred *Credentials) CreateO2AuthUser(rw http.ResponseWriter, r *http.Request, store *mysqlstore.MySQLStore, providerID, provider, email, name string) error {

	// work with database
	// looking for an existing user login, if google provider exist then generate JWT
	var userLogin database.MasterUserLogin
	if err := config.DB.Where("provider_key = ? && login_provider = ?", providerID, provider).First(&userLogin).Error; err == nil {

		return nil
	}

	// looking for an existing user , if not exist then create a new one
	var user database.MasterUser
	if err := config.DB.Where("username = ?", email).First(&user).Error; err != nil {
		rw.WriteHeader(http.StatusForbidden)

		return err
	}

	// proceed to create the new user with transaction scope
	err := config.DB.Transaction(func(tx *gorm.DB) error {
		// do some database operations in the transaction (use 'tx' from this point, not 'db')
		var newUser database.MasterUser
		var dbErr error

		newUser.RoleID = 1
		newUser.Username = email
		newUser.DisplayName = name
		newUser.Password, dbErr = bcrypt.GenerateFromPassword([]byte(string(providerID+strconv.Itoa(mathRand.Int()))), 10)
		if dbErr != nil {
			return dbErr
		}

		newUser.Email = email
		newUser.Created = time.Now().Local()
		newUser.CreatedBy = "SYSTEM"
		newUser.Modified = time.Now().Local()
		newUser.ModifiedBy = "SYSTEM"

		if dbErr = tx.Create(&newUser).Error; dbErr != nil {
			return dbErr
		}

		// add the room details into the database with transaction scope
		dbErr = tx.Transaction(func(tx2 *gorm.DB) error {

			// create the variable specific to the nested transaction
			var newUserLogin database.MasterUserLogin
			var dbErr2 error

			newUserLogin.UserID = newUser.ID
			newUserLogin.LoginProvider = "GOOGLE"
			newUserLogin.ProviderKey = providerID
			newUserLogin.Created = time.Now().Local()
			newUserLogin.CreatedBy = "SYSTEM"
			newUserLogin.Modified = time.Now().Local()
			newUserLogin.ModifiedBy = "SYSTEM"

			// insert the new room details to database
			if dbErr2 = tx2.Create(&newUserLogin).Error; dbErr2 != nil {
				return dbErr2
			}

			// return nil will commit the whole nested transaction
			return nil
		})

		if dbErr != nil {
			return dbErr
		}

		// return nil will commit the whole transaction
		return nil
	})

	// if transaction error
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)

		return err
	}

	return nil

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
