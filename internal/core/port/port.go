package port

import (
	"context"
	"net/http"
	"time"
	"user-vault/config"
	"user-vault/internal/core/domain"
)

// Handler defines the interface for user authentication and account-related HTTP handlers.
type Handler interface {
	UserLogin(w http.ResponseWriter, r *http.Request)            // Handles user login requests
	UserLogout(w http.ResponseWriter, r *http.Request)           // Handles user logout requests
	UserActivation(w http.ResponseWriter, r *http.Request)       // Handles account activation using a token
	UserPasswordReset(w http.ResponseWriter, r *http.Request)    // Handles user password reset via token
	UserForgotPassword(w http.ResponseWriter, r *http.Request)   // Handles forgot password requests and sends a reset link
	UserRefreshToken(w http.ResponseWriter, r *http.Request)     // Validates and refreshes user access tokens
	UserRegister(w http.ResponseWriter, r *http.Request)         // Handles new user registration
	UserResendActivation(w http.ResponseWriter, r *http.Request) // Resends account activation link/token to the user
}

// RepositoryMySQL defines the interface for all database operations using MySQL.
type RepositoryMySQL interface {
	AutoMigrate() // Performs automatic database schema migration

	GetUserByUserID(ctx context.Context, id int) (domain.User, error)                                        // Retrieves a user by user ID
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)                             // Retrieves a user by username
	GetUserDetailsWithPasswordByUserID(ctx context.Context, id int) (domain.User, error)                     // Retrieves a user by user ID
	GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error) // Gets the count of failed login attempts since the session start time
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt domain.UserLoginAttempt) (int, error)       // Creates a new user login attempt record
	CreateUser(ctx context.Context, userData domain.User) (int, error)                                       // Creates a new user

	GetActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error) // Retrieves activation data by token
	CreateActivation(ctx context.Context, tokenData domain.UserActivationToken) (int, error)    // Creates a new activation token record
	UpdatedActivationStatus(ctx context.Context, tokenId int, status int) error                 // Updates the status of an activation token
	UpdateUserStatus(ctx context.Context, userid int, status int) error                         // Updates a user’s account status (e.g., active/inactive)

	CreatePasswordReset(ctx context.Context, tokenData domain.UserPasswordReset) (int, error)         // Creates a password reset token
	GetPasswordResetByToken(ctx context.Context, token string) (domain.UserPasswordReset, error)      // Retrieves a password reset record using token
	UpdatePasswordResetStatus(ctx context.Context, id int, status int) error                          // Updates the status of a password reset token
	GetActivePasswordResetByUserID(ctx context.Context, userid int) (domain.UserPasswordReset, error) // Retrieves the active password reset request for a user
	UpdatePassword(ctx context.Context, userid int, password string) error                            // Updates the user’s password

	CreateRefreshToken(ctx context.Context, refreshTokenData domain.UserRefreshToken) (int, error) // Stores a refresh token in the database
	RevokeRefreshToken(ctx context.Context, userid int, refreshToken string) error                 // Revokes a user's refresh token
	GetRefreshTokenData(ctx context.Context, refreshToken string) (domain.UserRefreshToken, error) // Retrieves refresh token data
}

// Router defines the interface for setting up and starting HTTP routes and middleware.
type Router interface {
	SetupRoutes(apiConfig config.Api, logger Logger, authMiddlewareIns Auth, handler Handler)
	StartServer(port string) error // Starts the HTTP server on the specified port
}

// Cipher defines the interface for encrypting and decrypting strings.
type Cipher interface {
	Encrypt(text string) (string, error)       // Encrypts a plain text string and returns the encrypted version
	Decrypt(cryptoText string) (string, error) // Decrypts an encrypted string and returns the original plain text
	GetKey() string                            // Returns the key used for encryption/decryption
}

// Token defines the interface for creating and validating JWT access and refresh tokens.
type Token interface {
	CreateAccessToken(uid int, uname string, name string, expiry time.Time) (string, error) // Creates a new access token for a user
	CreateRefreshToken(uid int, expiry time.Time) (string, error)                           // Creates a new refresh token for a user
	GetRefreshTokenData(encryptedToken string) (int, time.Time, error)                      // Extracts user ID and expiry from a refresh token
}

// Auth defines the interface for API key and access token validation middleware.
type Auth interface {
	ValidateApiKey() http.Handler       // Returns middleware that validates API keys
	ValidateRefreshToken() http.Handler // Returns middleware that validates refresh token
}

// Logger defines the interface for structured and leveled logging.
type Logger interface {
	Debug(ctx context.Context, messages ...any) // Logs debug messages
	Info(ctx context.Context, messages ...any)  // Logs informational messages
	Warn(ctx context.Context, messages ...any)  // Logs warning messages
	Error(ctx context.Context, messages ...any) // Logs error messages
	Fatal(ctx context.Context, messages ...any) // Logs fatal messages and exits the application

	Debugf(ctx context.Context, template string, args ...any) // Logs formatted debug messages
	Infof(ctx context.Context, template string, args ...any)  // Logs formatted informational messages
	Warnf(ctx context.Context, template string, args ...any)  // Logs formatted warning messages
	Errorf(ctx context.Context, template string, args ...any) // Logs formatted error messages
	Fatalf(ctx context.Context, template string, args ...any) // Logs formatted fatal messages and exits the application

	Debugw(ctx context.Context, msg string, keysAndValues ...any) // Logs structured debug messages
	Infow(ctx context.Context, msg string, keysAndValues ...any)  // Logs structured informational messages
	Warnw(ctx context.Context, msg string, keysAndValues ...any)  // Logs structured warning messages
	Errorw(ctx context.Context, msg string, keysAndValues ...any) // Logs structured error messages
	Fatalw(ctx context.Context, msg string, keysAndValues ...any) // Logs structured fatal messages and exits the application

	Sync(ctx context.Context) error // Flushes any buffered log entries
}

type Messager interface {
	PublishActivationEmail(toAddress, subject, name, link string) error
	PublishPasswordResetEmail(toAddress, subject, name, link string) error
}
