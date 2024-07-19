package service

import (
	"context"
	"mayilon/src/types"
)

type List struct {
	User
}

type User interface {
	GetUseridByUsername(ctx context.Context, username string) int
	CheckLoginAttempt(ctx context.Context, userId int) int
	GetUserByUseridAndPassword(ctx context.Context, userid int, password string) types.User
	CreateUser(ctx context.Context, username, password, name string) types.User
}
