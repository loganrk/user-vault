package port

import (
	"context"

	"github.com/loganrk/user-vault/internal/core/domain"
)

type SvrList struct {
	User UserSvr
}

type UserSvr interface {
	Login(ctx context.Context, req domain.UserLoginClientRequest) (domain.UserLoginClientResponse, domain.ErrorRes)
	Logout(ctx context.Context, req domain.UserLogoutClientRequest) (domain.UserLogoutClientResponse, domain.ErrorRes)
	Register(ctx context.Context, req domain.UserRegisterClientRequest) (domain.UserRegisterClientResponse, domain.ErrorRes)

	ActivateUser(ctx context.Context, req domain.UserActivationClientRequest) (domain.UserActivationClientResponse, domain.ErrorRes)
	ResendActivation(ctx context.Context, req domain.UserResendActivationClientRequest) (domain.UserResendActivationClientResponse, domain.ErrorRes)
	ForgotPassword(ctx context.Context, req domain.UserForgotPasswordClientRequest) (domain.UserForgotPasswordClientResponse, domain.ErrorRes)
	ResetPassword(ctx context.Context, req domain.UserResetPasswordClientRequest) (domain.UserResetPasswordClientResponse, domain.ErrorRes)

	RefreshToken(ctx context.Context, req domain.UserRefreshTokenClientRequest) (domain.UserRefreshTokenClientResponse, domain.ErrorRes)
}
