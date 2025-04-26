package auth

import (
	"net/http"
	"time"
	"userVault/internal/core/port"
	"userVault/internal/utils"

	"golang.org/x/exp/slices"
)

// auth struct holds API keys and a Token instance for handling API authentication.
type auth struct {
	apiKeys  []string   // List of valid API keys
	tokenIns port.Token // Token interface for handling token-related operations
}

// New creates a new auth instance with the given API keys and Token instance.
func New(apiKeys []string, tokenIns port.Token) port.Auth {
	return &auth{
		apiKeys:  apiKeys,  // Initialize with the provided API keys
		tokenIns: tokenIns, // Initialize with the provided Token instance
	}
}

// ValidateApiKey returns an HTTP handler that checks if the request contains a valid API key.
func (a *auth) ValidateApiKey() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the access token from the Authorization header
		apiToken := r.Header.Get("Authorization")
		token := utils.ExtractBearerToken(apiToken)

		if token == "" {
			// If no API key is provided, respond with Unauthorized error.
			http.Error(w, "api key is required", http.StatusUnauthorized)
			return
		}

		// Check if the provided API key is valid
		if !slices.Contains(a.apiKeys, token) {
			// If the API key is invalid, respond with Unauthorized error.
			http.Error(w, "api key is invalid", http.StatusUnauthorized)
			return
		}

		// Set content type to JSON for successful validation.
		w.Header().Set("Content-Type", "application/json")
	})
}

// ValidateRefreshToken returns an HTTP handler that validates the refresh token from the Authorization header.
func (a *auth) ValidateRefreshToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the refresh token from the Authorization header
		refreshToken := r.Header.Get("Authorization")
		token := utils.ExtractBearerToken(refreshToken)
		if token == "" {
			// If no token is provided or token is malformed, respond with Unauthorized error.
			http.Error(w, "authorization header required", http.StatusUnauthorized)
			return
		}

		// Get user ID and expiration time from the token
		userid, expiresAt, err := a.tokenIns.GetRefreshTokenData(token)
		if err != nil {
			// If there’s an internal error while fetching token data, respond with internal server error.
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// If the token is invalid (no user ID found), respond with Bad Request error.
		if userid == 0 {
			http.Error(w, "incorrect token", http.StatusBadRequest)
			return
		}

		// If the token is expired, respond with Bad Request error.
		if expiresAt.Before(time.Now()) {
			http.Error(w, "token is expired", http.StatusBadRequest)
			return
		}

	})
}
