package user

import (
	"context"
	"net/http"
	"time"

	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/shared/constant"
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
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "fetch_user failed", "email", req.Email, "phone", req.Phone, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if login attempts limit is reached
	if errRes := u.blockIfLoginAttemptLimitReached(ctx, userData.Id); errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "block_if_login_attempt_limit_reached failed", "email", req.Email, "phone", req.Phone, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneVerified(userData, req.Email, req.Phone)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	userPassword, err := u.mysql.GetUserPasswordByUserID(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "get_user_password_by_user_id failed", "userId", userData.Id, "error", err.Error(), "exception", constant.DBException)
		return domain.UserLoginClientResponse{}, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       err.Error(),
			Exception: constant.DBException,
		}
	}

	// Validate password and log attempt
	if errRes := u.validatePasswordAndLogAttempt(ctx, req.Password, userPassword.Password, userPassword.Salt, userData.Id); errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "validate_password_and_log_attempt failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}

		return domain.UserLoginClientResponse{}, errRes
	}

	// Generate and store refresh token
	refreshToken, errRes := u.generateAndStoreRefreshToken(ctx, userData.Id)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "generate_and_store_refresh_token failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}

		return domain.UserLoginClientResponse{}, errRes
	}

	// Return refresh token to the client
	return domain.UserLoginClientResponse{RefreshToken: refreshToken}, domain.ErrorRes{}
}

// OAuthLogin handles the OAuth login process by verifying the OAuth token and retrieving the user data.
// It generates and returns a refresh token if the login is successful or creates a new user if not found.
func (u *userusecase) OAuthLogin(ctx context.Context, req domain.UserOAuthLoginClientRequest) (domain.UserLoginClientResponse, domain.ErrorRes) {

	// Verify the OAuth token using the provided provider and token
	email, name, err := u.oAuthProvider.VerifyToken(ctx, req.Provider, req.Token)
	if err != nil {
		u.logger.Error(ctx, "verify_token failed", "provider", req.Provider, "error", err.Error(), "exception", constant.AuthorizationException)
		return domain.UserLoginClientResponse{}, domain.ErrorRes{
			Code:      http.StatusUnauthorized,
			Message:   "Invalid OAuth token",
			Err:       err.Error(),
			Exception: constant.AuthorizationException,
		}
	}

	// Fetch user by email
	userData, errRes := u.fetchUserByEmail(ctx, email)
	if errRes.Code != 0 && errRes.Code != http.StatusNotFound {
		u.logger.Errorw(ctx, "fetch_user_by_email failed", "email", email, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if login attempts limit is reached
	if errRes := u.blockIfLoginAttemptLimitReached(ctx, userData.Id); errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "block_if_login_attempt_limit_reached failed", "email", email, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserLoginClientResponse{}, errRes
	}
	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	// If user not found, create a new user
	if userData == nil || userData.Id == 0 {
		userData.Id, errRes = u.createUserForOAuth(ctx, email, name)
		if errRes.Code != 0 {
			u.logger.Errorw(ctx, "create_user_for_o_auth failed", "email", email, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
			return domain.UserLoginClientResponse{}, errRes
		}
	}

	// Fetch updated user data by ID
	userData, errRes = u.fetchUserByID(ctx, userData.Id)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "fetch_user_by_id failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if the account is active
	if errRes := u.checkAccountIsActive(ctx, userData); errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	// Generate and store a refresh token
	refreshToken, errRes := u.generateAndStoreRefreshToken(ctx, userData.Id)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "generate_and_store_refresh_token failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserLoginClientResponse{}, errRes
	}

	// Return the refresh token to the client
	return domain.UserLoginClientResponse{RefreshToken: refreshToken}, domain.ErrorRes{}
}

// Logout handles user logout by validating the refresh token, revoking it, and logging the event.
func (u *userusecase) Logout(ctx context.Context, req domain.UserLogoutClientRequest) (domain.UserLogoutClientResponse, domain.ErrorRes) {
	// Validate the refresh token
	refreshData, errRes := u.validateRefreshToken(ctx, req.RefreshToken)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "validate_refresh_token failed", "token", req.RefreshToken, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)

		}
		return domain.UserLogoutClientResponse{}, errRes
	}

	// Revoke the refresh token
	errRes = u.revokeRefreshToken(ctx, refreshData.Id, refreshData.UserId, req.RefreshToken)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "revoke_refresh_token failed", "tokenId", refreshData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)

		return domain.UserLogoutClientResponse{}, errRes
	}

	// Return success response
	return domain.UserLogoutClientResponse{Message: "User logged out successfully"}, domain.ErrorRes{}
}

// RefreshToken handles the refresh token process by validating the token, checking the user's account status, and rotating the refresh token.
func (u *userusecase) RefreshToken(ctx context.Context, req domain.UserRefreshTokenClientRequest) (domain.UserRefreshTokenClientResponse, domain.ErrorRes) {
	// Validate the refresh token
	refreshData, errRes := u.validateRefreshToken(ctx, req.RefreshToken)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "validate_refresh_token failed", "token", req.RefreshToken, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	// Fetch the user by ID
	userData, errRes := u.fetchUserByID(ctx, refreshData.UserId)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "fetch_user_by_id failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
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
		u.logger.Errorw(ctx, "create_access_token failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	// Rotate the refresh token
	refreshTokenType, refreshToken, errRes := u.handleRefreshTokenRotation(ctx, userData.Id, req.RefreshToken, refreshData.Id)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "handle_refresh_token_rotation failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

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
		return "", "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       err.Error(),
			Exception: constant.DBException,
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
		return domain.UserTokens{}, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to fetch refresh token. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	if refreshData.Id == 0 || refreshData.Revoked {
		return domain.UserTokens{}, domain.ErrorRes{
			Code:      http.StatusBadRequest,
			Message:   "Token is revoked or incorrect",
			Exception: constant.TokenException,
		}
	}

	if time.Now().After(refreshData.ExpiresAt) {
		return domain.UserTokens{}, domain.ErrorRes{
			Code:      http.StatusBadRequest,
			Message:   "Token is incorrect or expired",
			Exception: constant.TokenException,
		}
	}

	return refreshData, domain.ErrorRes{}
}

// createAccessToken creates an access token for the user.
func (u *userusecase) createAccessToken(ctx context.Context, user *domain.User) (string, domain.ErrorRes) {
	accessToken, err := u.token.CreateAccessToken(user.Id, user.Email, user.Name, u.getAccessTokenExpiry())
	if err != nil {
		u.logger.Errorw(ctx, "Failed to create access token", "event", "user_access_token_failed", "userId", user.Id, "error", err)
		return "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create access token. error = " + err.Error(),
			Exception: constant.TokenException,
		}
	}
	return accessToken, domain.ErrorRes{}
}

// revokeRefreshToken revokes the specified refresh token.
func (u *userusecase) revokeRefreshToken(ctx context.Context, tokenID int, userID int, token string) domain.ErrorRes {
	if err := u.mysql.RevokeToken(ctx, tokenID); err != nil {
		return domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       err.Error(),
			Exception: constant.DBException,
		}
	}
	return domain.ErrorRes{}
}

// blockIfLoginAttemptLimitReached checks login attempts and blocks if the max is reached.
func (u *userusecase) blockIfLoginAttemptLimitReached(ctx context.Context, userId int) domain.ErrorRes {
	attemptCount, err := u.mysql.GetUserLoginFailedAttemptCount(ctx, userId, u.getLoginAttemptSessionPeriod())
	if err != nil {
		return domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to fetch login attempt count. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	if attemptCount >= u.getMaxLoginAttempt() {
		return domain.ErrorRes{
			Code:      http.StatusTooManyRequests,
			Message:   "Maximum login attempts reached. Please try again later.",
			Exception: constant.ValidationException,
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
		return "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create refresh token. error = " + err.Error(),
			Exception: constant.GenericException,
		}
	}

	refreshTokenData := domain.UserTokens{
		UserId:    userID,
		Token:     refreshToken,
		Type:      constant.TOKEN_TYPE_REFRESH,
		ExpiresAt: expiresAt,
	}

	_, err = u.mysql.CreateToken(ctx, refreshTokenData)
	if err != nil {
		return "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to store refresh token. error = " + err.Error(),
			Exception: constant.DBException,
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
		return domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create login attempt. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	if !passwordMatch {
		return domain.ErrorRes{
			Code:      http.StatusUnauthorized,
			Message:   "Username or password is incorrect",
			Exception: constant.ValidationException,
		}
	}

	return domain.ErrorRes{}
}
