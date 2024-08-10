package config

type Table interface {
	GetUser() string
	GetUserLoginAttemp() string
	GetUserActivationToken() string
	GetUserPasswordReset() string
	GetUserRefreshToken() string
}

func (t table) getPrefix() string {

	return t.Prefix
}

func (t table) GetUser() string {

	return t.getPrefix() + t.User
}
func (t table) GetUserLoginAttemp() string {

	return t.getPrefix() + t.UserLoginAttempt
}

func (t table) GetUserActivationToken() string {

	return t.getPrefix() + t.UserActivationToken
}

func (t table) GetUserPasswordReset() string {

	return t.getPrefix() + t.UserPasswordReset
}

func (t table) GetUserRefreshToken() string {

	return t.getPrefix() + t.UserRefreshToken
}
