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

func (u *userusecase) fetchUserByID(ctx context.Context, userID int) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByUserID(ctx, userID)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user data by ID",
			"event", "fetch_user_by_id_failed",
			"userId", userID,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return &domain.User{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:    http.StatusNotFound,
			Message: "Username is incorrect",
			Err:     nil,
		}
	}
	return &userData, domain.ErrorRes{}
}

// fetchUserByEmail validates if email is associated with a pending user account.
func (u *userusecase) fetchUserByEmail(ctx context.Context, email string) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByEmail(ctx, email)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user by email", "email", email, "error", err)
		return nil, domain.ErrorRes{Code: http.StatusInternalServerError, Message: "Internal server error", Err: err}
	}
	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:    http.StatusNotFound,
			Message: "Username is incorrect",
			Err:     nil,
		}
	}
	return &userData, domain.ErrorRes{}
}

// fetchUserByPhone validates if phone is associated with a pending user account.
func (u *userusecase) fetchUserByPhone(ctx context.Context, phone string) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByPhone(ctx, phone)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user by phone", "phone", phone, "error", err)
		return nil, domain.ErrorRes{Code: http.StatusInternalServerError, Message: "Internal server error", Err: err}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:    http.StatusNotFound,
			Message: "Username is incorrect",
			Err:     nil,
		}
	}
	return &userData, domain.ErrorRes{}
}

// checkAccountIsPending checks whether the user account is in a pending state.
func (u *userusecase) checkAccountIsPending(ctx context.Context, userData *domain.User) (bool, domain.ErrorRes) {
	if userData.Status != constant.USER_STATUS_PENDING {
		return false, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Account is not pending",
		}
	}
	return true, domain.ErrorRes{}
}

func (u *userusecase) checkAccountIsActive(ctx context.Context, user *domain.User) domain.ErrorRes {
	if user.Status != constant.USER_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "account is not active",
			"event", "inactive_user_check",
			"userId", user.Id,
			"code", http.StatusForbidden,
		)
		return domain.ErrorRes{
			Code:    http.StatusForbidden,
			Message: "Your account is not active. Please contact support.",
			Err:     nil,
		}
	}
	return domain.ErrorRes{}
}
