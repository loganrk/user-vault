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

// getVerificationTokenExpiry calculates and returns the expiry time for the verification token based on configuration.
func (u *userusecase) getVerificationTokenExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetVerificationTokenExpiry()) * time.Second)
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
		return nil, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to retrieve user by user id. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:      http.StatusNotFound,
			Message:   constant.MessageInvalidApiParameters,
			Err:       "user not found for user id",
			Exception: constant.ResourceNotFoundException,
		}
	}

	return &userData, domain.ErrorRes{}
}

// fetchUser retrieves the user data based on either email or phone number.
func (u *userusecase) fetchUser(ctx context.Context, email, phone string) (*domain.User, domain.ErrorRes) {
	var userData *domain.User
	var errRes domain.ErrorRes

	switch {
	case email != "":
		userData, errRes = u.fetchUserByEmail(ctx, email)
	case phone != "":
		userData, errRes = u.fetchUserByPhone(ctx, phone)
	default:
		return nil, domain.ErrorRes{
			Code:      http.StatusNotFound,
			Message:   constant.MessageInvalidApiParameters,
			Err:       "email and phone both are empty",
			Exception: constant.ResourceNotFoundException,
		}
	}

	return userData, errRes
}

// fetchUserByEmail retrieves a user using the provided email address.
func (u *userusecase) fetchUserByEmail(ctx context.Context, email string) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to retrieve user by user email. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:      http.StatusNotFound,
			Message:   constant.MessageInvalidApiParameters,
			Err:       "user not found for user email",
			Exception: constant.ResourceNotFoundException,
		}
	}

	return &userData, domain.ErrorRes{}
}

// fetchUserByPhone retrieves a user using the provided phone number.
func (u *userusecase) fetchUserByPhone(ctx context.Context, phone string) (*domain.User, domain.ErrorRes) {
	userData, err := u.mysql.GetUserByPhone(ctx, phone)
	if err != nil {
		return nil, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to retrieve user by user phone. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	if userData.Id == 0 {
		return nil, domain.ErrorRes{
			Code:      http.StatusNotFound,
			Message:   constant.MessageInvalidApiParameters,
			Err:       "user not found for user phone",
			Exception: constant.ResourceNotFoundException,
		}
	}

	return &userData, domain.ErrorRes{}
}

// checkAccountIsActive verifies if the user's account status is 'ACTIVE'.
func (u *userusecase) checkAccountIsActive(ctx context.Context, user *domain.User) domain.ErrorRes {
	if user.Status != constant.USER_STATUS_ACTIVE {
		return domain.ErrorRes{
			Code:      http.StatusForbidden,
			Message:   "account is not active",
			Exception: constant.ForbiddenException,
		}
	}

	return domain.ErrorRes{}
}

// validateUserToken validates a user's token by checking various conditions such as token existence, validity, revocation, and expiration.
func (u *userusecase) validateUserToken(ctx context.Context, tokenType int8, token string, userID int) (*domain.UserTokens, domain.ErrorRes) {
	// Fetch the last token for the user from the database using the provided user ID and token type.
	tokenData, err := u.mysql.GetUserLastTokenByUserId(ctx, tokenType, userID)
	if err != nil {
		return nil, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to retrieve last token by user id. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	if tokenData.Token != token {
		return nil, domain.ErrorRes{
			Code:      http.StatusBadRequest,
			Message:   "invalid token",
			Exception: constant.ValidationException,
		}

	}

	// Check if the token has been revoked.
	if tokenData.Revoked {
		return nil, domain.ErrorRes{
			Code:      http.StatusBadRequest,
			Message:   "token already invoked",
			Exception: constant.ValidationException,
		}
	}

	// Check if the token has expired.
	if tokenData.ExpiresAt.Before(time.Now()) {
		return nil, domain.ErrorRes{
			Code:      http.StatusBadRequest,
			Message:   "token already expired",
			Exception: constant.ValidationException,
		}
	}

	return &tokenData, domain.ErrorRes{}
}

func (u *userusecase) isEmailOrPhoneVerified(user *domain.User, email, phone string) domain.ErrorRes {
	if email != "" && !user.EmailVerified {
		return domain.ErrorRes{
			Code:      http.StatusForbidden,
			Message:   "email is not verified",
			Exception: constant.ForbiddenException,
		}
	}

	if phone != "" && !user.PhoneVerified {
		return domain.ErrorRes{
			Code:      http.StatusForbidden,
			Message:   "phone is not verified",
			Exception: constant.ForbiddenException,
		}
	}

	return domain.ErrorRes{}
}

func (u *userusecase) isEmailOrPhoneNotVerified(user *domain.User, email, phone string) domain.ErrorRes {
	if email != "" && user.EmailVerified {
		return domain.ErrorRes{
			Code:    http.StatusForbidden,
			Message: "Your email is already verified",
		}
	}

	if phone != "" && user.PhoneVerified {
		return domain.ErrorRes{
			Code:    http.StatusForbidden,
			Message: "Your phone is already verified",
		}
	}

	return domain.ErrorRes{}
}
