package config

type Api interface {
	GetUserLoginEnabled() bool
	GetUserLoginProperties() (string, string)

	GetUserOauthLoginEnabled() bool
	GetUserOauthLoginProperties() (string, string)

	GetUserRegisterEnabled() bool
	GetUserRegisterProperties() (string, string)

	GetUserVerifyEnabled() bool
	GetUserVerifyProperties() (string, string)

	GetUserResendVerificationEnabled() bool
	GetUserResendVerificationProperties() (string, string)

	GetUserForgotPasswordEnabled() bool
	GetUserForgotPasswordProperties() (string, string)

	GetUserPasswordResetEnabled() bool
	GetUserPasswordResetProperties() (string, string)

	GetUserRefreshTokenEnabled() bool
	GetUserRefreshTokenProperties() (string, string)

	GetUserLogoutEnabled() bool
	GetUserLogoutProperties() (string, string)
}

func (a api) GetUserLoginEnabled() bool {

	return a.UserLogin.Enabled
}

func (a api) GetUserLoginProperties() (string, string) {
	apiData := a.UserLogin

	return apiData.Method, apiData.Route
}

func (a api) GetUserOauthLoginEnabled() bool {

	return a.UserOAuthLogin.Enabled
}

func (a api) GetUserOauthLoginProperties() (string, string) {
	apiData := a.UserOAuthLogin

	return apiData.Method, apiData.Route
}

func (a api) GetUserRegisterEnabled() bool {

	return a.UserRegister.Enabled
}

func (a api) GetUserRegisterProperties() (string, string) {
	apiData := a.UserRegister

	return apiData.Method, apiData.Route
}

func (a api) GetUserVerifyEnabled() bool {

	return a.UserVerify.Enabled
}

func (a api) GetUserVerifyProperties() (string, string) {
	apiData := a.UserVerify

	return apiData.Method, apiData.Route
}

func (a api) GetUserResendVerificationEnabled() bool {

	return a.UserResendVerification.Enabled
}

func (a api) GetUserResendVerificationProperties() (string, string) {
	apiData := a.UserResendVerification

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

func (a api) GetUserRefreshTokenEnabled() bool {
	return a.UserRefreshToken.Enabled
}
func (a api) GetUserRefreshTokenProperties() (string, string) {
	apiData := a.UserRefreshToken

	return apiData.Method, apiData.Route
}

func (a api) GetUserLogoutEnabled() bool {
	return a.UserLogout.Enabled
}
func (a api) GetUserLogoutProperties() (string, string) {
	apiData := a.UserLogout

	return apiData.Method, apiData.Route
}
