package store

import (
	"context"
	"mayilon/src/types"
	"time"
)

type User interface {
	GetUserByID(ctx context.Context, id int) (types.User, error)
	GetUserByUsername(ctx context.Context, username string) (types.User, error)
	GetUserByUsernamePassword(ctx context.Context, username, password string) (types.User, error)
	GetUserLoginAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error)
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error)
}
