package user

import (
	"context"
	"net/http"
	"time"

	"github.com/loganrk/user-vault/config"
	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/core/port"
)

// userusecase struct holds the dependencies for the user service, including
// configuration, logger, MySQL repository, and token management.
type userusecase struct {
	logger        port.Logger
	mysql         port.RepositoryMySQL
	conf          config.User
	token         port.Token
	messager      port.Messager
	oAuthProvider port.OAuthProvider
}

// New initializes a new user service with required dependencies and returns it.
func New(loggerIns port.Logger, tokenIns port.Token, messageIns port.Messager, mysqlIns port.RepositoryMySQL, appName string, userConfIns config.User) port.UserSvr {
	return &userusecase{
		logger:   loggerIns,
		mysql:    mysqlIns,
		conf:     userConfIns,
		token:    tokenIns,
		messager: messageIns,
	}
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

// fetchUserByID retrieves the user record using the provided user ID.
func (u *userusecase) fetchUserByID(ctx context.Context, userID int) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByUserID(ctx, userID)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user data by ID",
			"event", "fetch_user_by_id_failed",
			"userId", userID,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return nil, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to retrieve user",
			Err:     err,
		}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:    http.StatusNotFound,
			Message: "User not found",
		}
	}

	return &userData, domain.ErrorRes{}
}

// fetchUserByEmail retrieves a user using the provided email address.
func (u *userusecase) fetchUserByEmail(ctx context.Context, email string) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByEmail(ctx, email)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user by email",
			"event", "fetch_user_by_email_failed",
			"email", email,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return nil, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to retrieve user by email",
			Err:     err,
		}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:    http.StatusNotFound,
			Message: "No user found with this email",
		}
	}

	return &userData, domain.ErrorRes{}
}

// fetchUserByPhone retrieves a user using the provided phone number.
func (u *userusecase) fetchUserByPhone(ctx context.Context, phone string) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByPhone(ctx, phone)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user by phone",
			"event", "fetch_user_by_phone_failed",
			"phone", phone,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return nil, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to retrieve user by phone",
			Err:     err,
		}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:    http.StatusNotFound,
			Message: "No user found with this phone number",
		}
	}

	return &userData, domain.ErrorRes{}
}

// checkAccountIsPending verifies if the user's account status is 'PENDING'.
func (u *userusecase) checkAccountIsPending(ctx context.Context, userData *domain.User) (bool, domain.ErrorRes) {
	if userData.Status != constant.USER_STATUS_PENDING {
		u.logger.Warnw(ctx, "account is not in pending state",
			"event", "pending_user_check_failed",
			"userId", userData.Id,
			"status", userData.Status,
			"code", http.StatusBadRequest,
		)
		return false, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Account is not in a pending state",
		}
	}
	return true, domain.ErrorRes{}
}

// checkAccountIsActive verifies if the user's account status is 'ACTIVE'.
func (u *userusecase) checkAccountIsActive(ctx context.Context, user *domain.User) domain.ErrorRes {
	if user.Status != constant.USER_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "account is not active",
			"event", "inactive_user_check",
			"userId", user.Id,
			"status", user.Status,
			"code", http.StatusForbidden,
		)
		return domain.ErrorRes{
			Code:    http.StatusForbidden,
			Message: "Your account is not active. Please contact support.",
		}
	}
	return domain.ErrorRes{}
}

func (u *userusecase) validateUserToken(ctx context.Context, tokenType int8, token string, userID int) (*domain.UserTokens, domain.ErrorRes) {
	tokenData, err := u.mysql.GetUserLastTokenByUserId(ctx, tokenType, userID)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch token",
			"userID", userID,
			"token", token,
			"error", err,
		)
		return nil, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to validate token",
			Err:     err,
		}
	}

	if tokenData.Id == 0 || tokenData.Token != token {
		u.logger.Warnw(ctx, "invalid or mismatched token",
			"userID", userID,
			"providedToken", token,
			"storedToken", tokenData.Token,
		)

		return nil, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Invalid or expired token",
		}
	}

	if tokenData.Revoked {
		u.logger.Warnw(ctx, "token already used",
			"userID", userID,
			"token", token,
		)

		return nil, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Token already used",
		}
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		u.logger.Warnw(ctx, "token expired",
			"userID", userID,
			"token", token,
			"expiresAt", tokenData.ExpiresAt,
		)
		return nil, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Token expired",
		}
	}

	return &tokenData, domain.ErrorRes{}
}
