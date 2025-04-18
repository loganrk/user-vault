package domain

import (
	"context"
)

type List struct {
	User UserSvr
}

type UserSvr interface {
	Login(ctx context.Context, req UserLoginClientRequest) (UserLoginClientResponse, ResponseError)
	Logout(ctx context.Context, req UserLogoutClientRequest) (UserLogoutClientResponse, ResponseError)
	Register(ctx context.Context, req UserRegisterClientRequest) (UserRegisterClientResponse, ResponseError)

	ActivateUser(ctx context.Context, req UserActivationClientRequest) (UserActivationClientResponse, ResponseError)
	ResendActivation(ctx context.Context, req UserResendActivationClientRequest) (UserResendActivationClientResponse, ResponseError)
	ForgotPassword(ctx context.Context, req UserForgotPasswordClientRequest) (UserForgotPasswordClientResponse, ResponseError)
	ResetPassword(ctx context.Context, req UserResetPasswordClientRequest) (UserResetPasswordClientResponse, ResponseError)

	ValidateRefreshToken(ctx context.Context, req UserRefreshTokenValidateClientRequest) (UserRefreshTokenValidateClientResponse, ResponseError)
}
