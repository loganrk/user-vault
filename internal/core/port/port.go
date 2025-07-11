package port

import (
	"context"
	"net/http"
	"time"

	"github.com/loganrk/user-vault/internal/core/domain"
)

// Handler defines the interface for user authentication and account-related HTTP handlers.
type Handler interface {
	UserLogin(w http.ResponseWriter, r *http.Request)              // Handles user login requests
	UserOAuthLogin(w http.ResponseWriter, r *http.Request)         // Handles user login requests with oAuth
	UserLogout(w http.ResponseWriter, r *http.Request)             // Handles user logout requests
	UserVerify(w http.ResponseWriter, r *http.Request)             // Handles account verification using a token
	UserPasswordReset(w http.ResponseWriter, r *http.Request)      // Handles user password reset via token
	UserForgotPassword(w http.ResponseWriter, r *http.Request)     // Handles forgot password requests and sends a reset link
	UserRefreshToken(w http.ResponseWriter, r *http.Request)       // Validates and refreshes user access tokens
	UserRegister(w http.ResponseWriter, r *http.Request)           // Handles new user registration
	UserResendVerification(w http.ResponseWriter, r *http.Request) // Resends account verification link/token to the user
}

// RepositoryMySQL defines the interface for all database operations using MySQL.
type RepositoryMySQL interface {
	AutoMigrate() // Performs automatic database schema migration

	GetUserByUserID(ctx context.Context, id int) (domain.User, error)      // Retrieves a user by user ID
	GetUserByEmail(ctx context.Context, email string) (domain.User, error) // Retrieves a user by email
	GetUserByEmailOrPhone(ctx context.Context, email string, phone string) (domain.User, error)
	GetUserByPhone(ctx context.Context, phone string) (domain.User, error)
	GetUserPasswordByUserID(ctx context.Context, userID int) (domain.User, error)

	GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error) // Gets the count of failed login attempts since the session start time
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt domain.UserLoginAttempt) (int, error)       // Creates a new user login attempt record
	CreateUser(ctx context.Context, userData domain.User) (int, error)                                       // Creates a new user
	UpdateEmailVerfied(ctx context.Context, userid int) error
	UpdatePhoneVerfied(ctx context.Context, userid int) error
	UpdatePassword(ctx context.Context, userid int, password string) error // Updates the user’s password

	CreateToken(ctx context.Context, tokenData domain.UserTokens) (int, error)                 // Creates a new token record
	GetUserToken(ctx context.Context, tokenType int8, token string) (domain.UserTokens, error) // Retrieves token data
	GetUserLastTokenByUserId(ctx context.Context, tokenType int8, userId int) (domain.UserTokens, error)
	RevokeToken(ctx context.Context, id int) error // Revokes a user's token
	RevokeAllTokens(ctx context.Context, tokenType int8, userID int) error
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

// GinMiddleware defines the interface for API key and access token validation middleware.
type GinMiddleware interface {
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
	RegisterVerification(topic string)
	PublishVerificationEmail(toAddress, subject, name, link string) error
	PublishVerificationPhone(phone, name, token string) error

	RegisterPasswordReset(topic string)
	PublishPasswordResetEmail(toAddress, subject, name, link string) error
	PublishPasswordResetPhone(phone, name, token string) error
}
type OAuthProvider interface {
	VerifyToken(ctx context.Context, provider string, token string) (string, string, error)
}
