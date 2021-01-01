package handlers

import (
	"net/http"
)

// GetInfo is a method to fetch authorized user info
func (authHandler *AuthHandler) GetInfo(rw http.ResponseWriter, r *http.Request) {

	rw.WriteHeader(http.StatusOK)
	return
}
