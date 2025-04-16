package domain

type UserLoginClientRequest interface {
	Validate() error
	GetUsername() string
	GetPassword() string
}

type UserActivationClientRequest interface {
	Validate() error
	GetToken() string
}

type UserForgotPasswordClientRequest interface {
	Validate() error
	GetUsername() string
}

type UserResetPasswordClientRequest interface {
	Validate() error
	GetToken() string
	GetPassword() string
}

type UserRegisterClientRequest interface {
	Validate() error
	GetUsername() string
	GetPassword() string
	GetName() string
}

type UserResendActivationClientRequest interface {
	Validate() error
	GetUsername() string
}

type UserLogoutClientRequest interface {
	Validate() error
	GetRefreshToken() string
}

type UserRefreshTokenValidateClientRequest interface {
	Validate() error
	GetRefreshToken() string
}
