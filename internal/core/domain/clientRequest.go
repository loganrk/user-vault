package domain

type UserLoginClientRequest struct {
	Email    string `json:"email" schema:"email" validate:"email"`
	Phone    string `json:"phone" schema:"phone" validate:"e164"`
	Password string `json:"password" schema:"password" validate:"required,min=8,max=32"`
}

type UserRegisterClientRequest struct {
	Email    string `json:"email" schema:"email" validate:"email"`
	Phone    string `json:"phone" schema:"phone" validate:"e164"`
	Password string `json:"password" schema:"password" validate:"required,password"`
	Name     string `json:"name" schema:"name" validate:"required"`
}

type UserForgotPasswordClientRequest struct {
	Email string `json:"email" schema:"email" validate:"email"`
	Phone string `json:"phone" schema:"phone" validate:"e164"`
}

type UserResetPasswordClientRequest struct {
	Email    string `json:"email" schema:"email" validate:"email"`
	Phone    string `json:"phone" schema:"phone" validate:"e164"`
	Token    string `json:"token" schema:"token" validate:"required"`
	Password string `json:"password" schema:"password" validate:"required,password"`
}

type UserResendActivationClientRequest struct {
	Email string `json:"email" schema:"username" validate:"email"`
	Phone string `json:"phone" schema:"phone" validate:"e164"`
}

type UserLogoutClientRequest struct {
	RefreshToken string `json:"refresh_token" schema:"refresh_token" validate:"required"`
}

type UserActivationClientRequest struct {
	Email string `json:"email" schema:"username" validate:"email"`
	Phone string `json:"phone" schema:"phone" validate:"e164"`
	Token string `json:"token" schema:"token" validate:"required"`
}

type UserRefreshTokenClientRequest struct {
	RefreshToken string `json:"refresh_token" schema:"refresh_token" validate:"required"`
}

type UserOAuthLoginClientRequest struct {
	Provider string `json:"provider" validate:"required,oneof=google"`
	Token    string `json:"token" validate:"required"`
}
