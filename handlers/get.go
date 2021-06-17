package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fakhripraya/authentication-service/data"
	"github.com/fakhripraya/authentication-service/database"
	"github.com/fakhripraya/authentication-service/entities"
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

	if err := authHandler.credentials.CreateO2AuthUser(rw, r, authHandler.store, gauth.ID, "GOOGLE", gauth.Email, gauth.Name); err != nil {
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

// GetFacebookLoginURL is a method to get the facebook oauth2 url
func (authHandler *AuthHandler) GetFacebookLoginURL(rw http.ResponseWriter, r *http.Request) {

	var url string

	url = authHandler.facebookOauthConfig.AuthCodeURL(authHandler.oauthStateString)
	err := data.ToJSON(url, rw)
	if err != nil {

		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	return
}

// GetFacebookLoginCallback is a method to respond to the facebook oauth2 callback
func (authHandler *AuthHandler) GetFacebookLoginCallback(rw http.ResponseWriter, r *http.Request) {

	content, err := authHandler.credentials.GetFacebookUserInfo(r.FormValue("state"), r.FormValue("code"))
	if err != nil {

		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	type FacebookLocation struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	type FacebookAge struct {
		Min uint `json:"min"`
	}

	type FacebookAuth struct {
		ID       string           `json:"id"`
		Name     string           `json:"name"`
		Email    string           `json:"email"`
		Location FacebookLocation `json:"location"`
		AgeRange FacebookAge      `json:"age_range"`
		Gender   string           `json:"gender"`
	}

	var fauth = &FacebookAuth{}

	err = json.Unmarshal(content, fauth)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	if err := authHandler.credentials.CreateO2AuthUser(rw, r, authHandler.store, fauth.ID, "FACEBOOK", fauth.Email, fauth.Name); err != nil {
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	// generate a JWT token for securing http request
	if err := authHandler.credentials.GenerateJWT(rw, r, authHandler.store, fauth.Email); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		data.ToJSON(&GenericError{Message: err.Error()}, rw)

		return
	}

	return
}
