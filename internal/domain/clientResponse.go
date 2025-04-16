package domain

type HTTPError interface {
	error
	StatusCode() int
	MessageText() string
	Unwrap() error
}

type UserLoginClientResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshTokenType string `json:"refresh_token_type,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
}

type UserRefreshTokenValidateClientResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshTokenType string `json:"refresh_token_type,omitempty"`
	RefreshToken     string `json:"refresh_token"`
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
