package request

import (
	"regexp"
)

type userLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type newUserActivation struct {
	Token string `json:"token"`
}

type userForgotPassword struct {
	Username string `json:"username"`
}

type userResetPassword struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type userRegister struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type userResendActivation struct {
	Username string `json:"username"`
}

type userLogout struct {
	RefreshToken string `json:"refresh_token"`
}

type userRefreshTokenValidate struct {
	RefreshToken string `json:"refresh_token"`
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
var passwordRegex = regexp.MustCompile(`^.{8,12}$`)
