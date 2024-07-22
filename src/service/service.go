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
	CheckLoginFailedAttempt(ctx context.Context, userId int) int
	CreateLoginAttempt(ctx context.Context, userId int, success bool) int
	CheckPassword(ctx context.Context, password string, passwordHash string, saltHash string) bool
	CreateUser(ctx context.Context, username, password, name string) int

	CreateActivationToken(ctx context.Context, userid int) (int, string)
	GetActivationLink(tokenId int, token string) string
	GetActivationEmailTemplate(ctx context.Context, name string, activationLink string) string
	SendActivation(ctx context.Context, email string, template string) int

	CreatePasswordResetToken(ctx context.Context, userid int) (int, string)
	GetPasswordResetLink(tokenId int, token string) string
	GetPasswordResetEmailTemplate(ctx context.Context, name string, passwordResetLink string) string
	SendPasswordReset(ctx context.Context, email string, template string) int
	GetPasswordResetDataByToken(ctx context.Context, token string) types.UserPasswordReset
	UpdatePassword(ctx context.Context, userid int, password string, saltHash string) bool
}
