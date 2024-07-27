package config

type Table interface {
	GetPrefix() string
	GetUser() string
	GetUserLoginAttemp() string
	GetUserActivationToken() string
	GetUserPasswordReset() string
}

func (t table) GetPrefix() string {

	return t.Prefix
}

func (t table) GetUser() string {

	return t.User
}
func (t table) GetUserLoginAttemp() string {

	return t.UserLoginAttempt
}

func (t table) GetUserActivationToken() string {

	return t.UserActivationToken
}

func (t table) GetUserPasswordReset() string {

	return t.UserPasswordReset
}
