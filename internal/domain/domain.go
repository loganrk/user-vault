package domain

import (
	"context"
)

type List struct {
	User UserSvr
}

type UserSvr interface {
	Login(ctx context.Context, username, password string) (UserLoginClientResponse, HTTPError)
	Logout(ctx context.Context, refreshToken string) (UserLogoutClientResponse, HTTPError)
	Register(ctx context.Context, username, password, name string) (UserRegisterClientResponse, HTTPError)

	ActivateUser(ctx context.Context, token string) (UserActivationClientResponse, HTTPError)
	ResendActivation(ctx context.Context, username string) (UserResendActivationClientResponse, HTTPError)
	ForgotPassword(ctx context.Context, username string) (UserForgotPasswordClientResponse, HTTPError)
	ResetPassword(ctx context.Context, token, newPassword string) (UserResetPasswordClientResponse, HTTPError)

	ValidateRefreshToken(ctx context.Context, refreshToken string) (UserRefreshTokenValidateClientResponse, HTTPError)
}
