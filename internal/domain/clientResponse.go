package domain

type ErrorRes struct {
	Code    int
	Message string
	Err     error
}

type UserLoginClientResponse struct {
	RefreshToken string `json:"refresh_token"`
}

type UserRefreshTokenClientResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshTokenType string `json:"refresh_token_type"`
	RefreshToken     string `json:"refresh_token,omitempty"`
}

type UserActivationClientResponse struct {
	Message string `json:"message"`
}

type UserForgotPasswordClientResponse struct {
	Message string `json:"message"`
}

type UserLogoutClientResponse struct {
	Message string `json:"message"`
}

type UserResetPasswordClientResponse struct {
	Message string `json:"message"`
}

type UserRegisterClientResponse struct {
	Message string `json:"message"`
}

type UserResendActivationClientResponse struct {
	Message string `json:"message"`
}
