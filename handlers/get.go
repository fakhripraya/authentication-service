package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/fakhripraya/authentication-service/config"
	"github.com/fakhripraya/authentication-service/data"
	"github.com/fakhripraya/authentication-service/database"
	"github.com/fakhripraya/authentication-service/entities"
	"github.com/jinzhu/gorm"
)

// GetAuthUser is a method to fetch the authorized user info
func (authHandler *AuthHandler) GetAuthUser(rw http.ResponseWriter, r *http.Request) {

	// get the current user login
	var authUser *database.MasterUser
	authUser, err := authHandler.credentials.GetCurrentUser(rw, r, authHandler.store)

	if err != nil {
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	// map the user credentials
	userInfo := entities.UserInfo{
		ID:             authUser.ID,
		RoleID:         authUser.RoleID,
		Username:       authUser.Username,
		DisplayName:    authUser.DisplayName,
		Email:          authUser.Email,
		Phone:          authUser.Phone,
		ProfilePicture: authUser.ProfilePicture,
		City:           authUser.City,
		LoginFailCount: authUser.LoginFailCount,
		IsVerified:     authUser.IsVerified,
		IsActive:       authUser.IsActive,
		Created:        authUser.Created,
		CreatedBy:      authUser.CreatedBy,
		Modified:       authUser.Modified,
		ModifiedBy:     authUser.ModifiedBy,
	}

	// parse the given instance to the response writer
	err = data.ToJSON(&userInfo, rw)
	if err != nil {

		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	return
}

// GetGoogleLoginURL is a method to get the google oauth2 url
func (authHandler *AuthHandler) GetGoogleLoginURL(rw http.ResponseWriter, r *http.Request) {

	var url string

	url = authHandler.googleOauthConfig.AuthCodeURL(authHandler.oauthStateString)
	err := data.ToJSON(url, rw)
	if err != nil {

		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	return
}

// GetGoogleLoginCallback is a method to respond to the google oauth2 callback
func (authHandler *AuthHandler) GetGoogleLoginCallback(rw http.ResponseWriter, r *http.Request) {

	content, err := authHandler.credentials.GetGoogleUserInfo(r.FormValue("state"), r.FormValue("code"))
	if err != nil {

		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	type GoogleAuth struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		FamilyName    string `json:"family_name"`
		GivenName     string `json:"given_name"`
		Locale        string `json:"locale"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
	}

	var gauth = &GoogleAuth{}

	err = json.Unmarshal(content, gauth)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	// work with database
	// looking for an existing user , if not exist then create a new one
	var user database.MasterUser
	if err := config.DB.Where("username = ?", gauth.Email).First(&user).Error; err == nil {
		// generate a JWT token for securing http request
		if err := authHandler.credentials.GenerateJWT(rw, r, authHandler.store, gauth.Email); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			data.ToJSON(&GenericError{Message: err.Error()}, rw)

			return
		}

		return
	}

	// proceed to create the new user with transaction scope
	err = config.DB.Transaction(func(tx *gorm.DB) error {
		// do some database operations in the transaction (use 'tx' from this point, not 'db')
		var newUser database.MasterUser
		var dbErr error

		newUser.RoleID = 1
		newUser.Username = gauth.Email
		newUser.DisplayName = gauth.Name

		newUser.Email = gauth.Email

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
			newUserLogin.LoginProvider = "Google"
			newUserLogin.ProviderKey = "107401105721129010945"
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
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	// generate a JWT token for securing http request
	if err := authHandler.credentials.GenerateJWT(rw, r, authHandler.store, gauth.Email); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	return
}
