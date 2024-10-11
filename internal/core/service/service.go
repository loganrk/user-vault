package service

import (
	"context"
	"mayilon/internal/core/domain"
	"time"
)

type List struct {
	User
}

type User interface {
	GetUserByUserid(ctx context.Context, userid int) (domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	CheckLoginFailedAttempt(ctx context.Context, userId int) (int, error)
	CreateLoginAttempt(ctx context.Context, userId int, success bool) (int, error)
	CheckPassword(ctx context.Context, password string, passwordHash string, saltHash string) (bool, error)
	CreateUser(ctx context.Context, username, password, name string) (int, error)

	CreateActivationToken(ctx context.Context, userid int) (int, string, error)
	GetActivationLink(tokenId int, token string) string
	GetActivationEmailTemplate(ctx context.Context, name string, activationLink string) (string, error)
	SendActivation(ctx context.Context, email string, template string) error
	GetUserActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error)
	UpdatedActivationtatus(ctx context.Context, tokenId int, status int) error
	UpdateStatus(ctx context.Context, userid int, status int) error

	CreatePasswordResetToken(ctx context.Context, userid int) (int, string, error)
	GetPasswordResetLink(token string) string
	GetPasswordResetEmailTemplate(ctx context.Context, name string, passwordResetLink string) (string, error)
	SendPasswordReset(ctx context.Context, email string, template string) error
	GetPasswordResetByToken(ctx context.Context, token string) (domain.UserPasswordReset, error)
	UpdatedPasswordResetStatus(ctx context.Context, tokenid int, status int) error
	UpdatePassword(ctx context.Context, userid int, password string, saltHash string) error

	RefreshTokenEnabled() bool
	RefreshTokenRotationEnabled() bool
	StoreRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) (int, error)
	RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error
	GetRefreshTokenData(ctx context.Context, userid int, token string) (domain.UserRefreshToken, error)
}
