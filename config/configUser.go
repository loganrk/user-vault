package config

type User interface {
	GetMaxLoginAttempt() int
	GetLoginAttemptSessionPeriod() int
	GetPasswordHashCost() int

	GetVerificationTokenExpiry() int
	GetPasswordResetTokenExpiry() int

	GetRefreshTokenEnabled() bool
	GetRefreshTokenRotationEnabled() bool
	GetRefreshTokenExpiry() int

	GetAccessTokenExpiry() int
}

func (u user) GetMaxLoginAttempt() int {

	return u.MaxLoginAttempt
}

func (u user) GetLoginAttemptSessionPeriod() int {

	return u.LoginAttemptSessionPeriod
}
func (u user) GetPasswordHashCost() int {

	return u.PasswordHashCost
}

func (u user) GetVerificationTokenExpiry() int {
	return u.Verification.TokenExpiry
}

func (u user) GetPasswordResetTokenExpiry() int {
	return u.PasswordReset.TokenExpiry
}

func (u user) GetRefreshTokenEnabled() bool {
	return u.RefreshToken.Enabled
}

func (u user) GetRefreshTokenRotationEnabled() bool {
	return u.RefreshToken.Rotation
}

func (u user) GetRefreshTokenExpiry() int {
	return u.RefreshToken.Expiry
}

func (u user) GetAccessTokenExpiry() int {
	return u.AccessToken.Expiry
}
