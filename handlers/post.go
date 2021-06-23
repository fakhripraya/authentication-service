package handlers

import (
	"net/http"
	"time"

	"github.com/fakhripraya/authentication-service/config"
	"github.com/fakhripraya/authentication-service/data"
	"github.com/fakhripraya/authentication-service/database"
	"github.com/fakhripraya/authentication-service/entities"
	"github.com/fakhripraya/authentication-service/mailer"

	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// OTPRegister is a method to validate the register otp
func (authHandler *AuthHandler) OTPRegister(rw http.ResponseWriter, r *http.Request) {

	// Currently nothing to do here ;)
	// return status 200 if otp middleware passed
	rw.WriteHeader(http.StatusOK)
	return
}

// OTPLogin is a method to validate the login otp
func (authHandler *AuthHandler) OTPLogin(rw http.ResponseWriter, r *http.Request) {

	// get the credential from the context
	cred := r.Context().Value(KeyCredentials{}).(*entities.CredentialsDB)

	// generate a JWT token for securing http request
	if err := authHandler.credentials.GenerateJWT(rw, r, authHandler.store, cred.Username); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	return
}

// Login to generate an authentication token to be used between client and server
func (authHandler *AuthHandler) Login(rw http.ResponseWriter, r *http.Request) {

	cred := r.Context().Value(KeyCredentials{}).(*entities.CredentialsDB)

	// work with database
	// looking for an existing user by matching user credentials
	var user database.MasterUser
	if err := config.DB.Where("username = ?", cred.Username).First(&user).Error; err != nil {
		rw.WriteHeader(http.StatusNotFound)
		data.ToJSON(&GenericError{Message: "Username tidak dapat ditemukan"}, rw)

		return
	}

	// looking for an existing user login, if provider exist, return with
	var userLogin database.MasterUserLogin
	if err := config.DB.Where("user_id = ?", user.ID).First(&userLogin).Error; err == nil {
		rw.WriteHeader(http.StatusForbidden)
		data.ToJSON(&GenericError{Message: "User sudah terdaftar dengan " + userLogin.LoginProvider + "silahkan login menggunakan provider tersebut."}, rw)

		return
	}

	// hashing a crypted password from the database to match
	// the encrypted password from the request
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(cred.Password)); err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		data.ToJSON(&GenericError{Message: "Password salah"}, rw)

		return
	}

	//generate OTP
	succ, err := authHandler.credentials.SendOTP(rw, r, &user, authHandler.store)
	if err != nil {
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

	} else {
		data.ToJSON(&GenericError{Message: succ}, rw)
	}

	return
}

// TODO: fix bug username yang sama masih bisa masuk database
// Register to create a new user and register it to a database endpoint
func (authHandler *AuthHandler) Register(rw http.ResponseWriter, r *http.Request) {

	// get the credentials via context
	cred := r.Context().Value(KeyCredentials{}).(*entities.CredentialsDB)

	// work with database
	// looking for an existing user , if not exist then create a new one
	// TODO: change 0 to 62 if input is phone number
	var user database.MasterUser
	if err := config.DB.Where("username = ?", cred.Username).First(&user).Error; err == nil {
		rw.WriteHeader(http.StatusForbidden)
		data.ToJSON(&GenericError{Message: "Username already exist"}, rw)

		return
	}

	// map the user credentials
	user = database.MasterUser{
		Username: cred.Username,
		Password: []byte(cred.Password),
	}

	// generate OTP
	succ, err := authHandler.credentials.SendOTP(rw, r, &user, authHandler.store)
	if err != nil {
		data.ToJSON(&GenericError{Message: err.Error()}, rw)
	} else {
		rw.WriteHeader(http.StatusOK)
		data.ToJSON(&GenericError{Message: succ}, rw)
	}

	return
}

// RegisterFinal is the final point of the registration function
func (authHandler *AuthHandler) RegisterFinal(rw http.ResponseWriter, r *http.Request) {

	// get the credentials via context
	cred := r.Context().Value(KeyCredentials{}).(*entities.CredentialsDB)

	// work with database
	// looking for an existing user , if not exist then create a new one
	var user database.MasterUser
	if err := config.DB.Where("username = ?", cred.Username).First(&user).Error; err == nil {
		rw.WriteHeader(http.StatusForbidden)
		data.ToJSON(&GenericError{Message: "Username already exist"}, rw)

		return
	}

	// proceed to create the new user with transaction scope
	err := config.DB.Transaction(func(tx *gorm.DB) error {
		// do some database operations in the transaction (use 'tx' from this point, not 'db')
		var newUser database.MasterUser
		var dbErr error

		newUser.RoleID = 1
		newUser.Username = cred.Username
		newUser.DisplayName = cred.Username
		newUser.Password, dbErr = bcrypt.GenerateFromPassword([]byte(cred.Password), 10)
		if dbErr != nil {
			return dbErr
		}

		// validate if the username was an email or not
		if mailer.IsEmailValid(cred.Username) {
			newUser.Email = cred.Username
		} else {
			newUser.Phone = cred.Username
		}

		newUser.Created = time.Now().Local()
		newUser.CreatedBy = "SYSTEM"
		newUser.Modified = time.Now().Local()
		newUser.ModifiedBy = "SYSTEM"

		if dbErr := tx.Create(&newUser).Error; dbErr != nil {
			return dbErr
		}

		// return nil will commit the whole transaction
		return nil
	})

	// if transaction error
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	// generate a JWT token for securing http request
	if err := authHandler.credentials.GenerateJWT(rw, r, authHandler.store, cred.Username); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}
}
