package store

import (
	"context"
	"mayilon/pkg/types"
	"time"

	"github.com/loganrk/go-db"
)

type User interface {
	GetUserByUserid(ctx context.Context, id int) (types.User, error)
	GetUserByUsername(ctx context.Context, username string) (types.User, error)
	GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error)
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error)
	CreateUser(ctx context.Context, userData types.User) (int, error)

	GetActivationByToken(ctx context.Context, token string) (types.UserActivationToken, error)
	CreateActivation(ctx context.Context, tokenData types.UserActivationToken) (int, error)
	UpdatedActivationtatus(ctx context.Context, tokenId int, status int) error
	UpdateStatus(ctx context.Context, userid int, status int) error

	CreatePasswordReset(ctx context.Context, tokenData types.UserPasswordReset) (int, error)
	GetPasswordResetByToken(ctx context.Context, token string) (types.UserPasswordReset, error)
	UpdatedPasswordResetStatus(ctx context.Context, id int, status int) error
	GetActivePasswordResetByUserId(ctx context.Context, userid int) (types.UserPasswordReset, error)
	UpdatePassword(ctx context.Context, userid int, password string) error

	CreateRefreshToken(ctx context.Context, refreshTokenData types.UserRefreshToken) (int, error)
	RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error
	GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) (types.UserRefreshToken, error)
}

func AutoMigrate(dbIns db.DB) {
	dbIns.GetDb().AutoMigrate(&types.User{}, &types.UserLoginAttempt{}, &types.UserActivationToken{}, &types.UserPasswordReset{}, &types.UserRefreshToken{})
}
