package store

import (
	"context"
	"mayilon/src/types"
	"time"
)

type User interface {
	GetUserByUserid(ctx context.Context, id int) (types.User, error)
	GetUserByUsername(ctx context.Context, username string) (types.User, error)
	GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error)
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error)
	CreateUser(ctx context.Context, userData types.User) (int, error)

	GetActivationTokenIdByToken(ctx context.Context, token string) (int, error)
	CreateActivationToken(ctx context.Context, tokenData types.UserActivationToken) (int, error)

	GetPasswordResetTokenIdByToken(ctx context.Context, token string) (int, error)
	CreatePasswordResetToken(ctx context.Context, tokenData types.UserPasswordReset) (int, error)
}
