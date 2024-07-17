package service

import (
	"context"
	"mayilon/src/types"
)

type List struct {
	User
}

type User interface {
	GetUserIdFromUsername(ctx context.Context, username string) int
	CheckLoginAttempt(ctx context.Context, userId int) int
	GetUserDataFromUsernameAndPassword(ctx context.Context, username, password string) types.User
}
