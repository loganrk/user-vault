package user

import (
	"context"
	"net/http"
	"time"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

func (u *userusecase) ForgotPassword(ctx context.Context, req domain.UserForgotPasswordClientRequest) (domain.UserForgotPasswordClientResponse, domain.ErrorRes) {

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
		return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Either email or phone is required",
		}
	}

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	// Send the activation token to the user's email or phone
	if req.Email != "" {
		// Generate a new activation token for the user
		tokenId, token, err := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, userData.Id)
		if err != nil || tokenId == 0 || token == "" {
			u.logger.Errorw(ctx, "failed to create activation token", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}

		// Send activation email
		if err := u.messager.PublishPasswordResetEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "failed to send activation email", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	} else {

		tokenId, token, err := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_ACTIVATION_PHONE, userData.Id)
		if err != nil || tokenId == 0 || token == "" {
			u.logger.Errorw(ctx, "failed to create activation token", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}

		// Send activation SMS
		if err := u.messager.PublishPasswordResetPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "failed to send activation SMS", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	}

	u.logger.Infow(ctx, "password reset request sent successfully", "event", "user_forgot_password_success", "userId", userData.Id)
	return domain.UserForgotPasswordClientResponse{Message: "Password reset request sent successfully"}, domain.ErrorRes{}
}

func (u *userusecase) ResetPassword(ctx context.Context, req domain.UserResetPasswordClientRequest) (domain.UserResetPasswordClientResponse, domain.ErrorRes) {
	var (
		userData  *domain.User
		errRes    domain.ErrorRes
		tokenType int8
	)

	// Check if email or phone is provided and fetch user data accordingly
	switch {
	case req.Email != "":
		userData, errRes = u.fetchUserByEmail(ctx, req.Email)
		tokenType = constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL
	case req.Phone != "":
		userData, errRes = u.fetchUserByPhone(ctx, req.Phone)
		tokenType = constant.TOKEN_TYPE_PASSWORD_RESET_PHONE
	default:
		// Return error if neither email nor phone is provided
		return domain.UserResetPasswordClientResponse{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Either email or phone is required",
		}
	}

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Fetch and validate the activation token
	tokenData, errRes := u.fetchAndValidateResetPasswordToken(ctx, tokenType, req.Token, userData.Id)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	errRes = u.updateUserPassword(ctx, userData, req.Password)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Revoke the activation token after successful activation
	if err := u.mysql.RevokeToken(ctx, tokenData.Id); err != nil {
		u.logger.Errorw(ctx, "failed to revoke activation token", "userId", userData.Id, "error", err)
		return domain.UserResetPasswordClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}

	u.logger.Infow(ctx, "user password reset successful", "event", "user_reset_password_success", "userId", userData.Id)
	return domain.UserResetPasswordClientResponse{Message: "Password has been reset successfully"}, domain.ErrorRes{}
}

// fetchAndValidateResetPasswordToken retrieves and validates activation token for the user.
func (u *userusecase) fetchAndValidateResetPasswordToken(ctx context.Context, tokenType int8, token string, userID int) (*domain.UserTokens, domain.ErrorRes) {
	tokenData, err := u.mysql.GetUserLastTokenByUserId(ctx, tokenType, userID)
	if err != nil || tokenData.Id == 0 {
		u.logger.Errorw(ctx, "invalid or expired token", "token", token, "error", err)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Invalid or expired token", Err: err}
	}

	// Validate token properties such as mismatch, already used, or expired
	if tokenData.Token != token {
		u.logger.Warnw(ctx, "token mismatch", "token", token)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Invalid password reset token"}
	}

	if tokenData.Revoked {
		u.logger.Warnw(ctx, "token already used", "token", token)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Password reset token already used"}
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		u.logger.Warnw(ctx, "token expired", "token", token)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Password reset token expired"}
	}

	return &tokenData, domain.ErrorRes{}
}

func (u *userusecase) updateUserPassword(ctx context.Context, userData *domain.User, password string) domain.ErrorRes {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+userData.Salt), u.conf.GetPasswordHashCost())
	if err != nil {
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	if err := u.mysql.UpdatePassword(ctx, userData.Id, string(hashPassword)); err != nil {
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	return domain.ErrorRes{}
}

// createActivationToken generates a new activation token and stores it in the DB.
func (u *userusecase) generatePasswordResetToken(ctx context.Context, tokenType int8, userID int) (int, string, error) {
	activationToken := utils.GenerateRandomString(25)

	// TODO: Revoke all existing tokens of same type for userID

	// Create token data object
	tokenData := domain.UserTokens{
		UserId:    userID,
		Token:     activationToken,
		Type:      tokenType,
		ExpiresAt: u.getPasswordResetTokenExpiry(),
	}

	// Store the generated token in DB
	tokenId, err := u.mysql.CreateToken(ctx, tokenData)
	if err != nil {
		return 0, "", err
	}

	return tokenId, activationToken, nil
}
