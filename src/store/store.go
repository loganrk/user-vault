package store

import (
	"context"
	"mayilon/src/types"
	"time"
)

type User interface {
	GetUserByID(ctx context.Context, id int) (types.User, error)
	GetUseridByUsername(ctx context.Context, username string) (int, error)
	GetUserByUseridAndPassword(ctx context.Context, userid int, password string) (types.User, error)
	GetUserLoginAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error)
	CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error)
	CreateUser(ctx context.Context, userData types.User) (types.User, error)
}
