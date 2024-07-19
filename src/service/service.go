package service

import (
	"context"
	"mayilon/src/types"
)

type List struct {
	User
	Email
}

type User interface {
	GetUserByUserid(ctx context.Context, userid int) types.User
	GetUseridByUsername(ctx context.Context, username string) int
	CheckLoginAttempt(ctx context.Context, userId int) int
	GetUserByUseridAndPassword(ctx context.Context, userid int, password string) types.User
	CreateUser(ctx context.Context, username, password, name string) types.User
}

type Email interface {
	SendUserActivation(ctx context.Context, userData types.User) int
}
