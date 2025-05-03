package user

import (
	"context"
	"net/http"

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
	tokenData, errRes := u.validateUserToken(ctx, tokenType, req.Token, userData.Id)
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

// updateUserPassword hashes and updates the user's password in the database.
func (u *userusecase) updateUserPassword(ctx context.Context, userData *domain.User, password string) domain.ErrorRes {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+userData.Salt), u.conf.GetPasswordHashCost())
	if err != nil {
		u.logger.Errorw(ctx, "password hashing failed",
			"event", "hashing_failed",
			"userID", userData.Id,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to reset password",
			Err:     err,
		}
	}

	err = u.mysql.UpdatePassword(ctx, userData.Id, string(hashPassword))
	if err != nil {
		u.logger.Errorw(ctx, "failed to update user password",
			"event", "update_password_failed",
			"userID", userData.Id,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update password",
			Err:     err,
		}
	}

	return domain.ErrorRes{}
}

// generatePasswordResetToken revokes old tokens and creates a new one for password reset.
func (u *userusecase) generatePasswordResetToken(ctx context.Context, tokenType int8, userID int) (int, string, error) {
	// Revoke all previous tokens
	if err := u.mysql.RevokeAllTokens(ctx, tokenType, userID); err != nil {
		u.logger.Errorw(ctx, "failed to revoke old tokens",
			"event", "revoke_tokens_failed",
			"userID", userID,
			"tokenType", tokenType,
			"error", err,
		)
		return 0, "", err
	}

	// Generate a new token
	activationToken := utils.GenerateRandomString(25)

	tokenData := domain.UserTokens{
		UserId:    userID,
		Token:     activationToken,
		Type:      tokenType,
		ExpiresAt: u.getPasswordResetTokenExpiry(),
	}

	// Store the token in the database
	tokenId, err := u.mysql.CreateToken(ctx, tokenData)
	if err != nil {
		u.logger.Errorw(ctx, "failed to store password reset token",
			"event", "create_token_failed",
			"userID", userID,
			"error", err,
		)
		return 0, "", err
	}

	return tokenId, activationToken, nil
}
