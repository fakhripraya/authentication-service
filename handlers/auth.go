package handlers

import (
	"github.com/fakhripraya/authentication-service/data"

	"github.com/hashicorp/go-hclog"
	"github.com/srinathgs/mysqlstore"
	"golang.org/x/oauth2"
)

// KeyCredentials is a key used for the Credentials object in the context
type KeyCredentials struct{}

// AuthHandler is a handler struct for authentication
type AuthHandler struct {
	logger              hclog.Logger
	credentials         *data.Credentials
	store               *mysqlstore.MySQLStore
	googleOauthConfig   *oauth2.Config
	facebookOauthConfig *oauth2.Config
	oauthStateString    string
}

// NewAuthHandler returns a new Auth handler with the given logger
func NewAuthHandler(newLogger hclog.Logger, newCredentials *data.Credentials, newStore *mysqlstore.MySQLStore, newGoogleOauthConfig *oauth2.Config, newFacebookOauthConfig *oauth2.Config, newOauthStateString string) *AuthHandler {
	return &AuthHandler{newLogger, newCredentials, newStore, newGoogleOauthConfig, newFacebookOauthConfig, newOauthStateString}
}

// GenericError is a generic error message returned by a server
type GenericError struct {
	Message string `json:"message"`
}
