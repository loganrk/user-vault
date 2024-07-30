package user

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
