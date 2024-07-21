package store

import (
	"context"
	"mayilon/src/types"
	"time"
)

type User interface {
	GetUserByUserid(ctx context.Context, id int) (types.User, error)
	GetUserByUsername(ctx context.Context, username string) (types.User, error)
	GetUserByUseridAndPassword(ctx context.Context, userid int, password string) (types.User, error)
	GetUserLoginAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error)
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error)
	CreateUser(ctx context.Context, userData types.User) (int, error)
	UserActivationTokenExists(ctx context.Context, token string) (bool, error)
	CreateActivationToken(ctx context.Context, tokenData types.UserActivationToken) (int, error)
}
