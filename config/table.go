package config

type Table interface {
	GetPrefix() string
	GetUser() string
	GetUserLoginAttemp() string
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
