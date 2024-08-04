package config

type Api interface {
	GetUserLoginEnabled() bool
	GetUserLoginProperties() (string, string)

	GetUserRegisterEnabled() bool
	GetUserRegisterProperties() (string, string)

	GetUserActivationEnabled() bool
	GetUserActivationProperties() (string, string)

	GetUserResendActivationEnabled() bool
	GetUserResendActivationProperties() (string, string)

	GetUserForgotPasswordEnabled() bool
	GetUserForgotPasswordProperties() (string, string)

	GetUserPasswordResetEnabled() bool
	GetUserPasswordResetProperties() (string, string)
}

func (a api) GetUserLoginEnabled() bool {

	return a.UserLogin.Enabled
}

func (a api) GetUserLoginProperties() (string, string) {
	apiData := a.UserLogin

	return apiData.Method, apiData.Route
}

func (a api) GetUserRegisterEnabled() bool {

	return a.UserRegister.Enabled
}

func (a api) GetUserRegisterProperties() (string, string) {
	apiData := a.UserRegister

	return apiData.Method, apiData.Route
}

func (a api) GetUserActivationEnabled() bool {

	return a.UserActivation.Enabled
}

func (a api) GetUserActivationProperties() (string, string) {
	apiData := a.UserActivation

	return apiData.Method, apiData.Route
}

func (a api) GetUserResendActivationEnabled() bool {

	return a.UserResendActivation.Enabled
}

func (a api) GetUserResendActivationProperties() (string, string) {
	apiData := a.UserResendActivation

	return apiData.Method, apiData.Route
}

func (a api) GetUserForgotPasswordEnabled() bool {

	return a.UserForgotPassword.Enabled
}

func (a api) GetUserForgotPasswordProperties() (string, string) {
	apiData := a.UserForgotPassword

	return apiData.Method, apiData.Route
}

func (a api) GetUserPasswordResetEnabled() bool {
	return a.UserPasswordReset.Enabled
}
func (a api) GetUserPasswordResetProperties() (string, string) {
	apiData := a.UserPasswordReset

	return apiData.Method, apiData.Route
}
