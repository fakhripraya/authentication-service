package handlers

import (
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
		LoginFailCount: authUser.LoginFailCount,
		IsVerified:     authUser.IsVerified,
		IsActive:       authUser.IsActive,
		Created:        authUser.Created,
		CreatedBy:      authUser.CreatedBy,
		Modified:       authUser.Modified,
		ModifiedBy:     authUser.ModifiedBy,
	}

	rw.WriteHeader(http.StatusOK)
	data.ToJSON(&userInfo, rw)
	return
}
