package domain

type ErrorRes struct {
	Code      int
	Message   string
	Err       string
	Exception string
}

type UserLoginClientResponse struct {
	RefreshToken string `json:"refresh_token"`
}

type UserRefreshTokenClientResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshTokenType string `json:"refresh_token_type"`
	RefreshToken     string `json:"refresh_token,omitempty"`
}

type UserVerifyClientResponse struct {
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

type UserResendVerificationClientResponse struct {
	Message string `json:"message"`
}
