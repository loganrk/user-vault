package service

import (
	"context"
	"mayilon/src/types"
)

type List struct {
	User
}

type User interface {
	GetUserByUserid(ctx context.Context, userid int) types.User
	GetUserByUsername(ctx context.Context, username string) types.User
	CheckLoginAttempt(ctx context.Context, userId int) int
	CreateLoginAttempt(ctx context.Context, userId int, success bool) int
	GetUserByUseridAndPassword(ctx context.Context, userid int, password string, saltHash string) types.User

	CreateUser(ctx context.Context, username, password, name string) int
	CreateActivationToken(ctx context.Context, userid int) (int, string)
	GetActivationLink(tokenId int, token string) string
	GetActivationEmailTemplate(ctx context.Context, name string, activationLink string) string
	SendUserActivation(ctx context.Context, email string, template string) int
}
