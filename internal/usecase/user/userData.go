package user

import (
	"context"
	"time"
	"userVault/internal/domain"
)

// getUserByUsername retrieves the user data based on the provided username.
// Returns the user data if found or an error if the user is not found or there's an issue with the DB query.
func (u *userusecase) getUserByUsername(ctx context.Context, username string) (domain.User, error) {
	userData, err := u.mysql.GetUserByUsername(ctx, username)
	return userData, err
}

// getUserByUserID retrieves the user data based on the provided user ID.
// Returns the user data if found or an error if the user is not found or there's an issue with the DB query.
func (u *userusecase) getUserByUserID(ctx context.Context, userid int) (domain.User, error) {
	userData, err := u.mysql.GetUserByUserID(ctx, userid)
	return userData, err
}

// getUserDetailsWithPasswordByUserID retrieves the user data based on the provided user ID.
// Returns the user data if found or an error if the user is not found or there's an issue with the DB query.
func (u *userusecase) getUserDetailsWithPasswordByUserID(ctx context.Context, userid int) (domain.User, error) {
	userData, err := u.mysql.GetUserDetailsWithPasswordByUserID(ctx, userid)
	return userData, err
}

// getUserLoginFailedAttemptCount retrieves the count of failed login attempts for the specified user ID.
// Takes the user ID and session start time to filter failed attempts in the given period.
// Returns the failed attempt count or an error if the query fails.
func (u *userusecase) getUserLoginFailedAttemptCount(ctx context.Context, userid int, sesstionStartTime time.Time) (int, error) {
	attempCount, err := u.mysql.GetUserLoginFailedAttemptCount(ctx, userid, sesstionStartTime)
	return attempCount, err
}

// createLoginAttempt logs a new login attempt for the user.
// Takes the user ID and a success flag to determine whether the attempt was successful or not.
// Returns the login attempt ID and any errors encountered.
func (u *userusecase) createLoginAttempt(ctx context.Context, userId int, success bool) (int, error) {
	loginAttemptId, err := u.mysql.CreateUserLoginAttempt(ctx, domain.UserLoginAttempt{
		UserId:    userId,
		Success:   success,
		CreatedAt: time.Now(),
	})
	return loginAttemptId, err
}

// createUser creates a new user record in the database.
// Takes the user data as input and returns the created user's ID or any errors encountered during the insertion.
func (u *userusecase) createUser(ctx context.Context, userData domain.User) (int, error) {
	userid, err := u.mysql.CreateUser(ctx, userData)
	return userid, err
}

// getActivePasswordResetByUserID retrieves an active password reset token for the given user ID.
// Returns the password reset data if found or an error if no active reset token is available or a query error occurs.
func (u *userusecase) getActivePasswordResetByUserID(ctx context.Context, userid int) (domain.UserPasswordReset, error) {
	passwordResetData, err := u.mysql.GetActivePasswordResetByUserID(ctx, userid)
	return passwordResetData, err
}

// getPasswordResetByToken retrieves password reset data by the token provided.
// Returns the password reset data if the token is found or an error if the token is invalid or the query fails.
func (u *userusecase) getPasswordResetByToken(ctx context.Context, passwordResetToken string) (domain.UserPasswordReset, error) {
	alreadyExiststData, err := u.mysql.GetPasswordResetByToken(ctx, passwordResetToken)
	return alreadyExiststData, err
}

// updatePasswordResetStatus updates the status of a password reset request based on its ID.
// Takes the password reset ID and the new status as input, and returns any errors encountered during the update.
func (u *userusecase) updatePasswordResetStatus(ctx context.Context, id int, status int) error {
	err := u.mysql.UpdatePasswordResetStatus(ctx, id, status)
	return err
}

// UpdatePassword updates the user's password in the database.
// Takes the user ID and the hashed password as input and returns any errors encountered during the update.
func (u *userusecase) UpdatePassword(ctx context.Context, userid int, hashPassword []byte) error {
	err := u.mysql.UpdatePassword(ctx, userid, string(hashPassword))
	return err
}

// storeRefreshToken stores a new refresh token in the database for the user.
// Takes the refresh token data and returns the refresh token ID or any errors encountered during storage.
func (u *userusecase) storeRefreshToken(ctx context.Context, refreshTokenData domain.UserRefreshToken) (int, error) {
	refreshTokenId, err := u.mysql.CreateRefreshToken(ctx, refreshTokenData)
	return refreshTokenId, err
}

// RevokeRefreshToken revokes an existing refresh token for the specified user.
// Takes the user ID and the refresh token as input and returns any errors encountered during the revocation process.
func (u *userusecase) RevokeRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	err := u.mysql.RevokeRefreshToken(ctx, userid, refreshToken)
	return err
}

// getRefreshTokenData retrieves refresh token data for the specified user and token.
// Takes therefresh token as input and returns the refresh token data or any errors encountered.
func (u *userusecase) getRefreshTokenData(ctx context.Context, refreshToken string) (domain.UserRefreshToken, error) {
	tokenData, err := u.mysql.GetRefreshTokenData(ctx, refreshToken)
	return tokenData, err
}

// getActivationByToken retrieves the activation token data for the given token.
// Returns the activation token data if found or an error if the token is invalid or not found.
func (u *userusecase) getActivationByToken(ctx context.Context, activationToken string) (domain.UserActivationToken, error) {
	tokenData, err := u.mysql.GetActivationByToken(ctx, activationToken)
	return tokenData, err
}

// createActivation creates a new activation token record for the user.
// Takes the activation token data and returns the activation token ID or any errors encountered during the creation process.
func (u *userusecase) createActivation(ctx context.Context, tokenData domain.UserActivationToken) (int, error) {
	tokenId, err := u.mysql.CreateActivation(ctx, tokenData)
	return tokenId, err
}

// getUserActivationByToken retrieves the user activation token data for the given token.
// Returns the activation token data if found or an error if the token is invalid or not found.
func (u *userusecase) getUserActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error) {
	tokenData, err := u.mysql.GetActivationByToken(ctx, token)
	return tokenData, err
}

// updatedActivationStatus updates the status of a user activation token based on its ID.
// Takes the activation token ID and the new status as input and returns any errors encountered during the update.
func (u *userusecase) UpdatedActivationStatus(ctx context.Context, id int, status int) error {
	err := u.mysql.UpdatedActivationStatus(ctx, id, status)
	return err
}

// updateStatus updates the user's status in the database.
// Takes the user ID and new status as input and returns any errors encountered during the update.
func (u *userusecase) updateUserStatus(ctx context.Context, userid int, status int) error {
	err := u.mysql.UpdateUserStatus(ctx, userid, status)
	return err
}

// getAccessTokenExpiry calculates and returns the expiry time for the access token based on configuration.
func (u *userusecase) getAccessTokenExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetAccessTokenExpiry()) * time.Second)
}

// refreshTokenEnabled checks if refresh tokens are enabled based on configuration.
func (u *userusecase) refreshTokenEnabled() bool {
	return u.conf.GetRefreshTokenEnabled()
}

// refreshTokenRotationEnabled checks if refresh token rotation is enabled based on configuration.
func (u *userusecase) refreshTokenRotationEnabled() bool {
	return u.conf.GetRefreshTokenRotationEnabled()
}

// getRefreshTokenExpiry calculates and returns the expiry time for the refresh token based on configuration.
func (u *userusecase) getRefreshTokenExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetRefreshTokenExpiry()) * time.Second)
}

// getActivationLinkExpiry calculates and returns the expiry time for the activation link based on configuration.
func (u *userusecase) getActivationLinkExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetActivationLinkExpiry()) * time.Second)
}

// getLoginAttemptSessionPeriod calculates and returns the session period for login attempts based on configuration.
func (u *userusecase) getLoginAttemptSessionPeriod() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetLoginAttemptSessionPeriod()*-1) * time.Second)
}

// getMaxLoginAttempt retrieves the maximum number of failed login attempts allowed from configuration.
func (u *userusecase) getMaxLoginAttempt() int {
	return u.conf.GetMaxLoginAttempt()
}

// getPasswordResetLinkExpiry calculates and returns the expiry time for the password reset link based on configuration.
func (u *userusecase) getPasswordResetLinkExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetPasswordResetLinkExpiry()) * time.Second)
}
