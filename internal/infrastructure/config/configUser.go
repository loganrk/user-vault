package config

type User interface {
	GetMaxLoginAttempt() int
	GetLoginAttemptSessionPeriod() int
	GetPasswordHashCost() int

	GetVerificationLink() string
	GetVerificationTokenExpiry() int

	GetPasswordResetLink() string
	GetPasswordResetTokenExpiry() int

	GetRefreshTokenEnabled() bool
	GetRefreshTokenRotationEnabled() bool
	GetRefreshTokenExpiry() int

	GetAccessTokenExpiry() int

	GetAppleClientId() string
	GetGoogleClientId() string
	GetMicrosoftClientId() string
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

func (u user) GetVerificationLink() string {
	return u.Verification.Link
}

func (u user) GetVerificationTokenExpiry() int {
	return u.Verification.TokenExpiry
}

func (u user) GetPasswordResetLink() string {
	return u.PasswordReset.Link
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

func (u user) GetAppleClientId() string {
	return u.AppleClientId
}

func (u user) GetGoogleClientId() string {
	return u.GoogleClientId
}

func (u user) GetMicrosoftClientId() string {
	return u.MicroSoftClientId
}
