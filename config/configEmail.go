package config

type Email interface {
	GetActivationLink() string
	GetActivationEmailTemplatePath() string
	GetPasswordResetLink() string
	GetPasswordResetTemplatePath() string
}

func (e email) GetPasswordResetLink() string {
	return e.PasswordReset.Link
}

func (e email) GetPasswordResetTemplatePath() string {
	return e.PasswordReset.TemplatePath
}

func (e email) GetActivationLink() string {
	return e.Activation.Link
}

func (e email) GetActivationEmailTemplatePath() string {
	return e.Activation.TemplatePath
}
