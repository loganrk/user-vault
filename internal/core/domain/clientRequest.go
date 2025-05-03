package domain

type UserLoginClientRequest struct {
	Username string `json:"username" schema:"username" validate:"required,email"`
	Password string `json:"password" schema:"password" validate:"required,min=8,max=32"`
}

type UserRegisterClientRequest struct {
	Username string `json:"username" schema:"username" validate:"required,email"`
	Password string `json:"password" schema:"password" validate:"required,password"`
	Name     string `json:"name" schema:"name" validate:"required"`
}

type UserForgotPasswordClientRequest struct {
	Username string `json:"username" schema:"username" validate:"required,email"`
}

type UserResetPasswordClientRequest struct {
	Token    string `json:"token" schema:"token" validate:"required"`
	Password string `json:"password" schema:"password" validate:"required,password"`
}

type UserResendActivationClientRequest struct {
	Username string `json:"username" schema:"username" validate:"required,email"`
}

type UserLogoutClientRequest struct {
	RefreshToken string `json:"refresh_token" schema:"refresh_token" validate:"required"`
}

type UserActivationClientRequest struct {
	Token string `json:"token" schema:"token" validate:"required"`
}

type UserRefreshTokenClientRequest struct {
	RefreshToken string `json:"refresh_token" schema:"refresh_token" validate:"required"`
}

type UserOAuthLoginClientRequest struct {
	Provider string `json:"provider" validate:"required,oneof=google"`
	Token    string `json:"token" validate:"required"`
}
