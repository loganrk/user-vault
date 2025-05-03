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

	// Check if email or phone is provided and fetch user data accordingly
	switch {
	case req.Email != "":
		userData, errRes = u.fetchUserByEmail(ctx, req.Email)
	case req.Phone != "":
		userData, errRes = u.fetchUserByPhone(ctx, req.Phone)
	default:
		// Return error if neither email nor phone is provided
		return domain.UserLoginClientResponse{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Either email or phone is required",
		}
	}

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	if errRes := u.blockIfLoginAttemptLimitReached(ctx, userData.Id); errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	if errRes := u.validatePasswordAndLogAttempt(ctx, req.Password, userData.Password, userData.Salt, userData.Id); errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	userData, errRes = u.fetchUserByID(ctx, userData.Id)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}
	refreshToken, errRes := u.generateAndStoreRefreshToken(ctx, userData.Id)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	// Log successful login
	u.logger.Infow(ctx, "user login successful",
		"event", "user_login_success",
		"userId", userData.Id,
		"code", http.StatusOK,
	)

	// Return refresh token to the client
	return domain.UserLoginClientResponse{
		RefreshToken: refreshToken,
	}, domain.ErrorRes{}
}

func (u *userusecase) OAuthLogin(ctx context.Context, req domain.UserOAuthLoginClientRequest) (domain.UserLoginClientResponse, domain.ErrorRes) {

	email, name, err := u.oAuthProvider.VerifyToken(ctx, req.Provider, req.Token)
	if err != nil {
		u.logger.Warnw(ctx, "oauth2 token verification failed", "provider", req.Provider, "error", err)
		return domain.UserLoginClientResponse{}, domain.ErrorRes{
			Code:    http.StatusUnauthorized,
			Message: "Invalid OAuth token",
		}
	}

	userData, errRes := u.fetchUserByEmail(ctx, email)
	if errRes.Code != 0 && errRes.Code != http.StatusNotFound {
		return domain.UserLoginClientResponse{}, errRes
	}

	if userData == nil || userData.Id == 0 {
		userData.Id, errRes = u.createUserForOAuth(ctx, email, name)
		if errRes.Code != 0 {
			return domain.UserLoginClientResponse{}, errRes
		}
	}

	userData, errRes = u.fetchUserByID(ctx, userData.Id)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	// Check if account is active
	if errRes := u.checkAccountIsActive(ctx, userData); errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	// Generate and store refresh token
	refreshToken, errRes := u.generateAndStoreRefreshToken(ctx, userData.Id)
	if errRes.Code != 0 {
		return domain.UserLoginClientResponse{}, errRes
	}

	u.logger.Infow(ctx, "user login successful",
		"event", "user_login_success",
		"userId", userData.Id,
		"code", http.StatusOK,
	)

	return domain.UserLoginClientResponse{
		RefreshToken: refreshToken,
	}, domain.ErrorRes{}

}

// Logout handles user logout by validating the refresh token, revoking it, and logging the event.
func (u *userusecase) Logout(ctx context.Context, req domain.UserLogoutClientRequest) (domain.UserLogoutClientResponse, domain.ErrorRes) {
	refreshData, errRes := u.validateRefreshToken(ctx, req.RefreshToken)
	if errRes.Code != 0 {
		return domain.UserLogoutClientResponse{}, errRes
	}

	errRes = u.revokeRefreshToken(ctx, refreshData.Id, refreshData.UserId, req.RefreshToken)
	if errRes.Code != 0 {
		return domain.UserLogoutClientResponse{}, errRes
	}

	u.logger.Infow(ctx, "user logged out successfully",
		"event", "logout_success",
		"userId", refreshData.UserId,
		"code", http.StatusOK,
	)
	return domain.UserLogoutClientResponse{}, domain.ErrorRes{}

}

func (u *userusecase) RefreshToken(ctx context.Context, req domain.UserRefreshTokenClientRequest) (domain.UserRefreshTokenClientResponse, domain.ErrorRes) {
	refreshData, errRes := u.validateRefreshToken(ctx, req.RefreshToken)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	userData, errRes := u.fetchUserByID(ctx, refreshData.UserId)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	accessToken, errRes := u.createAccessToken(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	refreshTokenType, refreshToken, errRes := u.handleRefreshTokenRotation(ctx, userData.Id, req.RefreshToken, refreshData.Id)
	if errRes.Code != 0 {
		return domain.UserRefreshTokenClientResponse{}, errRes
	}

	u.logger.Infow(ctx, "refresh token rotated successfully",
		"event", "user_refresh_token_success",
		"userId", userData.Id,
		"code", http.StatusOK,
	)

	return domain.UserRefreshTokenClientResponse{
		AccessToken:      accessToken,
		RefreshTokenType: refreshTokenType,
		RefreshToken:     refreshToken,
	}, domain.ErrorRes{}

}

func (u *userusecase) handleRefreshTokenRotation(ctx context.Context, userId int, oldToken string, oldTokenId int) (string, string, domain.ErrorRes) {
	if !u.refreshTokenRotationEnabled() {
		return constant.REFRESH_TOKEN_TYPE_STATIC, oldToken, domain.ErrorRes{}
	}

	if err := u.mysql.RevokeToken(ctx, oldTokenId); err != nil {
		u.logger.Errorw(ctx, "unable to revoke refresh token",
			"event", "user_refresh_token_failed", "userId", userId, "error", err)
		return "", "", domain.ErrorRes{Code: http.StatusInternalServerError, Message: "Unable to revoke token", Err: err}
	}

	newToken, errRes := u.generateAndStoreRefreshToken(ctx, userId)

	if errRes.Code != 0 {
		return "", "", errRes
	}

	return constant.REFRESH_TOKEN_TYPE_ROTATING, newToken, domain.ErrorRes{}
}

func (u *userusecase) validateRefreshToken(ctx context.Context, token string) (domain.UserTokens, domain.ErrorRes) {
	refreshData, err := u.mysql.GetUserToken(ctx, constant.TOKEN_TYPE_REFRESH, token)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch refresh token data",
			"event", "user_refresh_token_fetch_failed",
			"refreshToken", token,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.UserTokens{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if refreshData.Id == 0 || refreshData.Revoked {
		u.logger.Warnw(ctx, "revoked or invalid refresh token",
			"event", "user_refresh_token_invalid",
			"refreshToken", token,
			"code", http.StatusBadRequest,
		)
		return domain.UserTokens{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is revoked or incorrect",
			Err:     nil,
		}
	}

	if time.Now().After(refreshData.ExpiresAt) {
		u.logger.Warnw(ctx, "refresh token expired",
			"event", "refresh_token_expired",
			"refreshToken", token,
			"expiresAt", refreshData.ExpiresAt,
			"code", http.StatusBadRequest,
		)
		return domain.UserTokens{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is incorrect or expired",
			Err:     nil,
		}
	}

	return refreshData, domain.ErrorRes{}
}

func (u *userusecase) createAccessToken(ctx context.Context, user *domain.User) (string, domain.ErrorRes) {
	accessToken, err := u.token.CreateAccessToken(user.Id, user.Email, user.Name, u.getAccessTokenExpiry())
	if err != nil {
		u.logger.Errorw(ctx, "failed to create access token",
			"event", "user_refresh_token_failed", "userId", user.Id, "error", err)
		return "", domain.ErrorRes{Code: http.StatusInternalServerError, Message: "Internal server error", Err: err}
	}
	return accessToken, domain.ErrorRes{}
}

func (u *userusecase) revokeRefreshToken(ctx context.Context, tokenID int, userID int, token string) domain.ErrorRes {
	if err := u.mysql.RevokeToken(ctx, tokenID); err != nil {
		u.logger.Errorw(ctx, "unable to revoke refresh token",
			"event", "logout_failed",
			"userId", userID,
			"refreshToken", token,
			"error", err,
			"code", http.StatusInternalServerError,
		)
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
	// Get the number of failed login attempts within the defined session period
	attempCount, err := u.mysql.GetUserLoginFailedAttemptCount(ctx, userId, u.getLoginAttemptSessionPeriod())

	if err != nil {
		u.logger.Errorw(ctx, "error checking failed login attempts",
			"event", "login_attempt_check_failed",
			"userId", userId,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	// If the maximum number of failed attempts is reached, return the corresponding code
	if attempCount >= u.getMaxLoginAttempt() {
		u.logger.Warnw(ctx, "max login attempts reached",
			"event", "login_blocked",
			"userId", userId,
			"code", http.StatusTooManyRequests,
		)
		return domain.ErrorRes{
			Code:    http.StatusTooManyRequests,
			Message: "Maximum login attempts reached. Please try again later.",
			Err:     nil,
		}
	}

	return domain.ErrorRes{} // no error
}

func (u *userusecase) generateAndStoreRefreshToken(ctx context.Context, userID int) (string, domain.ErrorRes) {
	if !u.refreshTokenEnabled() {
		return "", domain.ErrorRes{}
	}

	expiresAt := u.getRefreshTokenExpiry()
	refreshToken, err := u.token.CreateRefreshToken(userID, expiresAt)
	if err != nil {
		u.logger.Errorw(ctx, "failed to create refresh token",
			"event", "refresh_token_generation_failed",
			"userId", userID,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return "", domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	// Prepare the refresh token data
	refreshTokenData := domain.UserTokens{
		UserId:    userID,
		Token:     refreshToken,
		Type:      constant.TOKEN_TYPE_REFRESH,
		ExpiresAt: expiresAt,
	}

	// Store the refresh token in the database
	_, err = u.mysql.CreateToken(ctx, refreshTokenData)
	if err != nil {
		u.logger.Errorw(ctx, "failed to store refresh token",
			"event", "refresh_token_storage_failed",
			"userId", userID,
			"error", err,
			"code", http.StatusInternalServerError,
		)
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
	// Use bcrypt to compare the password with the hashed value
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password+saltHash))
	if err == nil {
		passwordMatch = true
	}
	loginAttempt := domain.UserLoginAttempt{
		UserId:  userId,
		Success: passwordMatch,
	}
	// Log the login attempt (true for success, false for failure)
	_, err = u.mysql.CreateUserLoginAttempt(ctx, loginAttempt)
	if err != nil {
		u.logger.Errorw(ctx, "failed to create the login attempt",
			"event", "login_attempt_create_failed",
			"userId", userId,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if !passwordMatch {
		u.logger.Warnw(ctx, "password did not match",
			"event", "password_mismatch",
			"userId", userId,
			"code", http.StatusUnauthorized,
		)
		return domain.ErrorRes{
			Code:    http.StatusUnauthorized,
			Message: "Username or password is incorrect",
			Err:     nil,
		}
	}

	return domain.ErrorRes{} // No error
}
