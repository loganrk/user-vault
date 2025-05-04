package user

import (
	"context"
	"net/http"
	"time"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"golang.org/x/crypto/bcrypt"
)

// Login handles the user login process, performing checks like verifying username, password, login attempts, and user status.
// It generates and returns access and refresh tokens if the login is successful.
func (u *userusecase) Login(ctx context.Context, req domain.UserLoginClientRequest) (domain.UserLoginClientResponse, domain.ErrorRes) {

	var (
		userData *domain.User
		errRes   domain.ErrorRes
	)
	userData, errRes = u.fetchUser(ctx, req.Email, req.Phone)

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "User fetch failed", "event", "user_login_failed", "user", req, "error", errRes.Message, "code", errRes.Code)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if login attempts limit is reached
	if errRes := u.blockIfLoginAttemptLimitReached(ctx, userData.Id); errRes.Code != 0 {
		u.logger.Warnw(ctx, "Login attempt limit reached", "event", "user_login_failed", "userId", userData.Id, "code", errRes.Code, "error", errRes.Message)
		return domain.UserLoginClientResponse{}, errRes
	}
	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "Account inactive", "event", "user_login_failed", "userId", userData.Id, "error", errRes.Message, "code", errRes.Code)
		return domain.UserLoginClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneVerified(userData, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "User email or phone verification failed", "event", "user_login_failed", "user", req, "error", errRes.Message, "code", errRes.Code)
		return domain.UserLoginClientResponse{}, errRes
	}

	userPassword, err := u.mysql.GetUserPasswordByUserID(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "Unable to fetch the user password", "event", "user_login_failed", "userId", userData.Id, "error", err)
		return domain.UserLoginClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	// Validate password and log attempt
	if errRes := u.validatePasswordAndLogAttempt(ctx, req.Password, userPassword.Password, userPassword.Salt, userData.Id); errRes.Code != 0 {
		u.logger.Warnw(ctx, "Invalid password attempt", "event", "user_login_failed", "userId", userData.Id, "code", errRes.Code, "error", errRes.Message)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Generate and store refresh token
	refreshToken, errRes := u.generateAndStoreRefreshToken(ctx, userData.Id)
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "Failed to generate refresh token", "event", "user_login_failed", "userId", userData.Id, "error", errRes.Message, "code", errRes.Code)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Log successful login
	u.logger.Infow(ctx, "User login successful", "event", "user_login_success", "userId", userData.Id, "code", http.StatusOK)

	// Return refresh token to the client
	return domain.UserLoginClientResponse{RefreshToken: refreshToken}, domain.ErrorRes{}
}

// OAuthLogin handles the OAuth login process by verifying the OAuth token and retrieving the user data.
// It generates and returns a refresh token if the login is successful or creates a new user if not found.
func (u *userusecase) OAuthLogin(ctx context.Context, req domain.UserOAuthLoginClientRequest) (domain.UserLoginClientResponse, domain.ErrorRes) {

	// Verify the OAuth token using the provided provider and token
	email, name, err := u.oAuthProvider.VerifyToken(ctx, req.Provider, req.Token)
	if err != nil {
		// Log the error if token verification fails
		u.logger.Warnw(ctx, "OAuth2 token verification failed", "provider", req.Provider, "error", err)
		return domain.UserLoginClientResponse{}, domain.ErrorRes{
			Code:    http.StatusUnauthorized,
			Message: "Invalid OAuth token",
		}
	}

	// Fetch user by email
	userData, errRes := u.fetchUserByEmail(ctx, email)
	if errRes.Code != 0 && errRes.Code != http.StatusNotFound {
		// Log the error and return if fetching user data fails
		u.logger.Warnw(ctx, "Failed to fetch user by email", "email", email, "error", errRes.Message)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if login attempts limit is reached
	if errRes := u.blockIfLoginAttemptLimitReached(ctx, userData.Id); errRes.Code != 0 {
		u.logger.Warnw(ctx, "Login attempt limit reached", "event", "user_login_failed", "userId", userData.Id, "code", errRes.Code, "error", errRes.Message)
		return domain.UserLoginClientResponse{}, errRes
	}
	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "Account inactive", "event", "user_login_failed", "userId", userData.Id, "error", errRes.Message, "code", errRes.Code)
		return domain.UserLoginClientResponse{}, errRes
	}

	// If user not found, create a new user
	if userData == nil || userData.Id == 0 {
		userData.Id, errRes = u.createUserForOAuth(ctx, email, name)
		if errRes.Code != 0 {
			// Log the error and return if user creation fails
			u.logger.Warnw(ctx, "Failed to create user for OAuth", "email", email, "error", errRes.Message)
			return domain.UserLoginClientResponse{}, errRes
		}
	}

	// Fetch updated user data by ID
	userData, errRes = u.fetchUserByID(ctx, userData.Id)
	if errRes.Code != 0 {
		// Log the error and return if fetching updated user data fails
		u.logger.Warnw(ctx, "Failed to fetch user by ID", "userId", userData.Id, "error", errRes.Message)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if the account is active
	if errRes := u.checkAccountIsActive(ctx, userData); errRes.Code != 0 {
		// Log the error and return if the account is inactive
		u.logger.Warnw(ctx, "Account is inactive", "userId", userData.Id, "error", errRes.Message)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Generate and store a refresh token
	refreshToken, errRes := u.generateAndStoreRefreshToken(ctx, userData.Id)
	if errRes.Code != 0 {
		// Log the error and return if generating the refresh token fails
		u.logger.Warnw(ctx, "Failed to generate refresh token", "userId", userData.Id, "error", errRes.Message)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Log successful login
	u.logger.Infow(ctx, "User login successful", "event", "user_login_success", "userId", userData.Id, "code", http.StatusOK)

	// Return the refresh token to the client
	return domain.UserLoginClientResponse{RefreshToken: refreshToken}, domain.ErrorRes{}
}

// Logout handles user logout by validating the refresh token, revoking it, and logging the event.
func (u *userusecase) Logout(ctx context.Context, req domain.UserLogoutClientRequest) (domain.UserLogoutClientResponse, domain.ErrorRes) {
	// Validate the refresh token
	refreshData, errRes := u.validateRefreshToken(ctx, req.RefreshToken)
	if errRes.Code != 0 {
		return domain.UserLogoutClientResponse{}, errRes
	}

	// Revoke the refresh token
	errRes = u.revokeRefreshToken(ctx, refreshData.Id, refreshData.UserId, req.RefreshToken)
	if errRes.Code != 0 {
		return domain.UserLogoutClientResponse{}, errRes
	}

	// Log successful logout
	u.logger.Infow(ctx, "User logged out successfully", "event", "logout_success", "userId", refreshData.UserId, "code", http.StatusOK)

	// Return success response
	return domain.UserLogoutClientResponse{Message: "User logged out successfully"}, domain.ErrorRes{}
}

// RefreshToken handles the refresh token process by validating the token, checking the user's account status, and rotating the refresh token.
func (u *userusecase) RefreshToken(ctx context.Context, req domain.UserRefreshTokenClientRequest) (domain.UserRefreshTokenClientResponse, domain.ErrorRes) {
	// Validate the refresh token
	refreshData, errRes := u.validateRefreshToken(ctx, req.RefreshToken)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	// Fetch the user by ID
	userData, errRes := u.fetchUserByID(ctx, refreshData.UserId)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	// Create a new access token
	accessToken, errRes := u.createAccessToken(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	// Rotate the refresh token
	refreshTokenType, refreshToken, errRes := u.handleRefreshTokenRotation(ctx, userData.Id, req.RefreshToken, refreshData.Id)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	// Log successful refresh token rotation
	u.logger.Infow(ctx, "Refresh token rotated successfully", "event", "user_refresh_token_success", "userId", userData.Id, "code", http.StatusOK)

	// Return the new access and refresh tokens
	return domain.UserRefreshTokenClientResponse{
		AccessToken:      accessToken,
		RefreshTokenType: refreshTokenType,
		RefreshToken:     refreshToken,
	}, domain.ErrorRes{}
}

// handleRefreshTokenRotation rotates the refresh token if enabled, otherwise returns the old token.
func (u *userusecase) handleRefreshTokenRotation(ctx context.Context, userId int, oldToken string, oldTokenId int) (string, string, domain.ErrorRes) {
	if !u.refreshTokenRotationEnabled() {
		return constant.REFRESH_TOKEN_TYPE_STATIC, oldToken, domain.ErrorRes{}
	}

	if err := u.mysql.RevokeToken(ctx, oldTokenId); err != nil {
		u.logger.Errorw(ctx, "Unable to revoke refresh token", "event", "user_refresh_token_failed", "userId", userId, "error", err)
		return "", "", domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}

	newToken, errRes := u.generateAndStoreRefreshToken(ctx, userId)
	if errRes.Code != 0 {
		return "", "", errRes
	}

	return constant.REFRESH_TOKEN_TYPE_ROTATING, newToken, domain.ErrorRes{}
}

// validateRefreshToken validates the refresh token by checking its validity, expiry, and revocation status.
func (u *userusecase) validateRefreshToken(ctx context.Context, token string) (domain.UserTokens, domain.ErrorRes) {
	refreshData, err := u.mysql.GetUserToken(ctx, constant.TOKEN_TYPE_REFRESH, token)
	if err != nil {
		u.logger.Errorw(ctx, "Failed to fetch refresh token data", "event", "user_refresh_token_fetch_failed", "refreshToken", token, "error", err, "code", http.StatusInternalServerError)
		return domain.UserTokens{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	if refreshData.Id == 0 || refreshData.Revoked {
		u.logger.Warnw(ctx, "Revoked or invalid refresh token", "event", "user_refresh_token_invalid", "refreshToken", token, "code", http.StatusBadRequest)
		return domain.UserTokens{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is revoked or incorrect",
			Err:     nil,
		}
	}

	if time.Now().After(refreshData.ExpiresAt) {
		u.logger.Warnw(ctx, "Refresh token expired", "event", "refresh_token_expired", "refreshToken", token, "expiresAt", refreshData.ExpiresAt, "code", http.StatusBadRequest)
		return domain.UserTokens{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is incorrect or expired",
			Err:     nil,
		}
	}

	return refreshData, domain.ErrorRes{}
}

// createAccessToken creates an access token for the user.
func (u *userusecase) createAccessToken(ctx context.Context, user *domain.User) (string, domain.ErrorRes) {
	accessToken, err := u.token.CreateAccessToken(user.Id, user.Email, user.Name, u.getAccessTokenExpiry())
	if err != nil {
		u.logger.Errorw(ctx, "Failed to create access token", "event", "user_refresh_token_failed", "userId", user.Id, "error", err)
		return "", domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}
	return accessToken, domain.ErrorRes{}
}

// revokeRefreshToken revokes the specified refresh token.
func (u *userusecase) revokeRefreshToken(ctx context.Context, tokenID int, userID int, token string) domain.ErrorRes {
	if err := u.mysql.RevokeToken(ctx, tokenID); err != nil {
		u.logger.Errorw(ctx, "Unable to revoke refresh token", "event", "logout_failed", "userId", userID, "refreshToken", token, "error", err, "code", http.StatusInternalServerError)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}
	return domain.ErrorRes{}
}

// blockIfLoginAttemptLimitReached checks login attempts and blocks if the max is reached.
func (u *userusecase) blockIfLoginAttemptLimitReached(ctx context.Context, userId int) domain.ErrorRes {
	attempCount, err := u.mysql.GetUserLoginFailedAttemptCount(ctx, userId, u.getLoginAttemptSessionPeriod())

	if err != nil {
		u.logger.Errorw(ctx, "error checking failed login attempts", "event", "login_attempt_check_failed", "userId", userId, "error", err, "code", http.StatusInternalServerError)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if attempCount >= u.getMaxLoginAttempt() {
		u.logger.Warnw(ctx, "max login attempts reached", "event", "login_blocked", "userId", userId, "code", http.StatusTooManyRequests)
		return domain.ErrorRes{
			Code:    http.StatusTooManyRequests,
			Message: "Maximum login attempts reached. Please try again later.",
			Err:     nil,
		}
	}

	return domain.ErrorRes{}
}

func (u *userusecase) generateAndStoreRefreshToken(ctx context.Context, userID int) (string, domain.ErrorRes) {
	if !u.refreshTokenEnabled() {
		return "", domain.ErrorRes{}
	}

	expiresAt := u.getRefreshTokenExpiry()
	refreshToken, err := u.token.CreateRefreshToken(userID, expiresAt)
	if err != nil {
		u.logger.Errorw(ctx, "failed to create refresh token", "event", "refresh_token_generation_failed", "userId", userID, "error", err, "code", http.StatusInternalServerError)
		return "", domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	refreshTokenData := domain.UserTokens{UserId: userID, Token: refreshToken, Type: constant.TOKEN_TYPE_REFRESH, ExpiresAt: expiresAt}

	_, err = u.mysql.CreateToken(ctx, refreshTokenData)
	if err != nil {
		u.logger.Errorw(ctx, "failed to store refresh token", "event", "refresh_token_storage_failed", "userId", userID, "error", err, "code", http.StatusInternalServerError)
		return "", domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	return refreshToken, domain.ErrorRes{}
}

func (u *userusecase) validatePasswordAndLogAttempt(ctx context.Context, password, storedHash, saltHash string, userId int) domain.ErrorRes {
	var passwordMatch bool
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password+saltHash))
	if err == nil {
		passwordMatch = true
	}
	loginAttempt := domain.UserLoginAttempt{UserId: userId, Success: passwordMatch}

	_, err = u.mysql.CreateUserLoginAttempt(ctx, loginAttempt)
	if err != nil {
		u.logger.Errorw(ctx, "failed to create the login attempt", "event", "login_attempt_create_failed", "userId", userId, "error", err, "code", http.StatusInternalServerError)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if !passwordMatch {
		u.logger.Warnw(ctx, "password did not match", "event", "password_mismatch", "userId", userId, "code", http.StatusUnauthorized)
		return domain.ErrorRes{
			Code:    http.StatusUnauthorized,
			Message: "Username or password is incorrect",
			Err:     nil,
		}
	}

	return domain.ErrorRes{}
}
