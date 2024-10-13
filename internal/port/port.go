package port

import (
	"context"
	"mayilon/internal/domain"
	"net/http"
	"time"
)

type Handler interface {
	UserLogin(w http.ResponseWriter, r *http.Request)
	UserLogout(w http.ResponseWriter, r *http.Request)
	UserActivation(w http.ResponseWriter, r *http.Request)
	UserPasswordReset(w http.ResponseWriter, r *http.Request)
	UserForgotPassword(w http.ResponseWriter, r *http.Request)
	UserRefreshTokenValidate(w http.ResponseWriter, r *http.Request)
	UserRegister(w http.ResponseWriter, r *http.Request)
	UserResendActivation(w http.ResponseWriter, r *http.Request)
}

type RepositoryMySQL interface {
	AutoMigrate()

	GetUserByUserid(ctx context.Context, id int) (domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error)
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt domain.UserLoginAttempt) (int, error)
	CreateUser(ctx context.Context, userData domain.User) (int, error)

	GetActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error)
	CreateActivation(ctx context.Context, tokenData domain.UserActivationToken) (int, error)
	UpdatedActivationtatus(ctx context.Context, tokenId int, status int) error
	UpdateStatus(ctx context.Context, userid int, status int) error

	CreatePasswordReset(ctx context.Context, tokenData domain.UserPasswordReset) (int, error)
	GetPasswordResetByToken(ctx context.Context, token string) (domain.UserPasswordReset, error)
	UpdatedPasswordResetStatus(ctx context.Context, id int, status int) error
	GetActivePasswordResetByUserId(ctx context.Context, userid int) (domain.UserPasswordReset, error)
	UpdatePassword(ctx context.Context, userid int, password string) error

	CreateRefreshToken(ctx context.Context, refreshTokenData domain.UserRefreshToken) (int, error)
	RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error
	GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) (domain.UserRefreshToken, error)
}

type Router interface {
	RegisterRoute(method, path string, handlerFunc http.HandlerFunc)
	StartServer(port string) error
	UseBefore(middlewares ...http.HandlerFunc)
	NewGroup(groupName string) RouterGroup
}

type RouterGroup interface {
	RegisterRoute(method, path string, handlerFunc http.HandlerFunc)
	UseBefore(middlewares ...http.HandlerFunc)
}

type Cipher interface {
	Encrypt(text string) (string, error)
	Decrypt(cryptoText string) (string, error)
	GetKey() string
}

type Token interface {
	CreateAccessToken(uid int, uname string, name string, expiry time.Time) (string, error)
	CreateRefreshToken(uid int, expiry time.Time) (string, error)
	GetRefreshTokenData(tokenStringEcr string) (int, time.Time, error)
	GetRefreshTokenExpiry(tokenStringEcr string) (time.Time, error)
	GetAccessTokenData(encryptedToken string) (int, time.Time, error)
}

type Auth interface {
	ValidateApiKey() http.HandlerFunc
	ValidateAccessToken() http.HandlerFunc
}

type Logger interface {
	Debug(ctx context.Context, messages ...any)
	Info(ctx context.Context, messages ...any)
	Warn(ctx context.Context, messages ...any)
	Error(ctx context.Context, messages ...any)
	Fatal(ctx context.Context, messages ...any)
	Debugf(ctx context.Context, template string, args ...any)
	Infof(ctx context.Context, template string, args ...any)
	Warnf(ctx context.Context, template string, args ...any)
	Errorf(ctx context.Context, template string, args ...any)
	Fatalf(ctx context.Context, template string, args ...any)
	Debugw(ctx context.Context, msg string, keysAndValues ...any)
	Infow(ctx context.Context, msg string, keysAndValues ...any)
	Warnw(ctx context.Context, msg string, keysAndValues ...any)
	Errorw(ctx context.Context, msg string, keysAndValues ...any)
	Fatalw(ctx context.Context, msg string, keysAndValues ...any)
	Sync(ctx context.Context) error
}
