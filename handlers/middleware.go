package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/fakhripraya/authentication-service/data"
	"github.com/fakhripraya/authentication-service/entities"

	jwt "github.com/dgrijalva/jwt-go"
)

// MiddlewareValidateAuth validates the  request and calls next if ok
func (authHandler *AuthHandler) MiddlewareValidateAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		// Get a session (existing/new)
		session, err := authHandler.store.Get(r, "session-name")
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			data.ToJSON(&GenericError{Message: err.Error()}, rw)

			// TODO: redirect to login
			return
		}

		// check the token from the session
		// if token available, get the token from the session
		if session.Values["token"] == nil {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		// determine the cookie value that holds the token
		tokenString := session.Values["token"].(string)

		if tokenString != "" {

			// Initialize a new instance of claims
			claims := &data.Claims{}

			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Error while parsing the token with claims")
				}

				return []byte(data.MySigningKey), nil
			})

			if err != nil {
				if err == jwt.ErrSignatureInvalid {
					rw.WriteHeader(http.StatusUnauthorized)
					data.ToJSON(&GenericError{Message: err.Error()}, rw)

					// TODO: redirect to login
					return
				}

				rw.WriteHeader(http.StatusBadRequest)
				data.ToJSON(&GenericError{Message: err.Error()}, rw)

				// TODO: redirect to login
				return
			}

			if token.Valid {

				// create a new token for the current use, with a renewed expiration time
				expirationTime := time.Now().Add(time.Second * 86400 * 7)
				claims.StandardClaims.ExpiresAt = expirationTime.Unix()
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, err := token.SignedString([]byte(data.MySigningKey))

				if err != nil {
					rw.WriteHeader(http.StatusInternalServerError)
					data.ToJSON(&GenericError{Message: err.Error()}, rw)

					// TODO: redirect to login
					return
				}

				// renew the token in the session
				session.Options.MaxAge = 86400 * 7
				session.Values["token"] = tokenString
				session.Save(r, rw)

				next.ServeHTTP(rw, r)
			} else {
				rw.WriteHeader(http.StatusUnauthorized)
				data.ToJSON(&GenericError{Message: "Token invalid"}, rw)

				// TODO: redirect to login
				return
			}
		} else {
			rw.WriteHeader(http.StatusUnauthorized)
			data.ToJSON(&GenericError{Message: "Token invalid"}, rw)

			// TODO: redirect to login
			return
		}
	})
}

// MiddlewareParseCredentialsRequest parses the credentials payload in the request body from json
func (authHandler *AuthHandler) MiddlewareParseCredentialsRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// validate content type to be application/json
		rw.Header().Add("Content-Type", "application/json")

		// create the credentials instance
		cred := &entities.CredentialsDB{}

		// parse the request body to the given instance
		err := data.FromJSON(cred, r.Body)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			data.ToJSON(&GenericError{Message: err.Error()}, rw)

			return
		}

		// add the credentials to the context
		ctx := context.WithValue(r.Context(), KeyCredentials{}, cred)
		r = r.WithContext(ctx)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

// MiddlewareCheckOTP checks if the OTP code match
func (authHandler *AuthHandler) MiddlewareCheckOTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		// get the credentials via context
		cred := r.Context().Value(KeyCredentials{}).(*entities.CredentialsDB)

		// Get a session (existing/new)
		session, err := authHandler.store.Get(r, "session-name")
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			data.ToJSON(&GenericError{Message: err.Error()}, rw)

			return
		}

		// check the otp from the session
		// if otp code available, get the otp code from the session
		if session.Values["otp"] == nil {
			rw.WriteHeader(http.StatusNotFound)
			return
		}

		otpCode := session.Values["otp"].(string)

		if cred.OTPCode == otpCode {
			// Call the next handler, which can be another middleware in the chain, or the final handler.
			next.ServeHTTP(rw, r)
		} else {
			rw.WriteHeader(http.StatusForbidden)
			data.ToJSON(&GenericError{Message: "Invalid OTP Code"}, rw)

			return
		}
	})
}
