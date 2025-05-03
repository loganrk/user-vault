package user

import (
	"context"
	"time"

	"github.com/loganrk/user-vault/internal/core/domain"
)

// getUserByUsername retrieves the user data based on the provided username.
// Returns the user data if found or an error if the user is not found or there's an issue with the DB query.
func (u *userusecase) getUserByUsername(ctx context.Context, username string) (domain.User, error) {
	userData, err := u.mysql.GetUserByUsername(ctx, username)
	return userData, err
}

// getUserByEmail retrieves the user data based on the provided email.
// Returns the user data if found or an error if the user is not found or there's an issue with the DB query.
func (u *userusecase) getUserByEmail(ctx context.Context, email string) (domain.User, error) {
	userData, err := u.mysql.GetUserByEmail(ctx, email)
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

// UpdatePassword updates the user's password in the database.
// Takes the user ID and the hashed password as input and returns any errors encountered during the update.
func (u *userusecase) UpdatePassword(ctx context.Context, userid int, hashPassword []byte) error {
	err := u.mysql.UpdatePassword(ctx, userid, string(hashPassword))
	return err
}

// revokeToken revokes an existing token for the specified user.
// Takes the token ID as input and returns any errors encountered during the revocation process.
func (u *userusecase) revokeToken(ctx context.Context, id int) error {
	err := u.mysql.RevokeToken(ctx, id)
	return err
}

// getUserToken retrieves refresh token data for the specified type and token.
// Takes token as input and returns the token data or any errors encountered.
func (u *userusecase) getUserToken(ctx context.Context, tokenType int8, token string) (domain.UserTokens, error) {
	tokenData, err := u.mysql.GetUserToken(ctx, tokenType, token)
	return tokenData, err
}

// getUserToken retrieves refresh token data for the specified type and token.
// Takes token as input and returns the token data or any errors encountered.
func (u *userusecase) getUserLastTokenByUserId(ctx context.Context, tokenType int8, userId int) (domain.UserTokens, error) {
	tokenData, err := u.mysql.GetUserLastTokenByUserId(ctx, tokenType, userId)
	return tokenData, err
}

// createToken creates a new token record for the user.
// Takes the  token data and returns the token ID or any errors encountered during the creation process.
func (u *userusecase) createToken(ctx context.Context, tokenData domain.UserTokens) (int, error) {
	tokenId, err := u.mysql.CreateToken(ctx, tokenData)
	return tokenId, err
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

// getActivationTokenExpiry calculates and returns the expiry time for the activation token based on configuration.
func (u *userusecase) getActivationTokenExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetActivationTokenExpiry()) * time.Second)
}

// getLoginAttemptSessionPeriod calculates and returns the session period for login attempts based on configuration.
func (u *userusecase) getLoginAttemptSessionPeriod() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetLoginAttemptSessionPeriod()*-1) * time.Second)
}

// getMaxLoginAttempt retrieves the maximum number of failed login attempts allowed from configuration.
func (u *userusecase) getMaxLoginAttempt() int {
	return u.conf.GetMaxLoginAttempt()
}

// getPasswordResetTokenExpiry calculates and returns the expiry time for the password reset based on configuration.
func (u *userusecase) getPasswordResetTokenExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetPasswordResetTokenExpiry()) * time.Second)
}
