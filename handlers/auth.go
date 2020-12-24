package handlers

import (
	"github.com/fakhripraya/authentication-service/data"

	"github.com/hashicorp/go-hclog"
	"github.com/srinathgs/mysqlstore"
)

// KeyCredentials is a key used for the Credentials object in the context
type KeyCredentials struct{}

// AuthHandler is a handler struct for authentication
type AuthHandler struct {
	logger      hclog.Logger
	credentials *data.Credentials
	store       *mysqlstore.MySQLStore
}

// NewAuth returns a new Auth handler with the given logger
func NewAuth(newLogger hclog.Logger, newCredentials *data.Credentials, newStore *mysqlstore.MySQLStore) *AuthHandler {
	return &AuthHandler{newLogger, newCredentials, newStore}
}

// GenericError is a generic error message returned by a server
type GenericError struct {
	Message string `json:"message"`
}
