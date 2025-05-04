package user

import (
	"context"
	"net/http"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// ForgotPassword handles the user request for resetting their password.
func (u *userusecase) ForgotPassword(ctx context.Context, req domain.UserForgotPasswordClientRequest) (domain.UserForgotPasswordClientResponse, domain.ErrorRes) {
	var (
		userData *domain.User
		errRes   domain.ErrorRes
	)
	userData, errRes = u.fetchUser(ctx, req.Email, req.Phone)

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	// Generate and send the activation token to the user's email or phone
	if req.Email != "" {
		// Generate a new activation token for email-based password reset
		tokenId, token, err := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, userData.Id)
		if err != nil || tokenId == 0 || token == "" {
			// Log error if token generation failed
			u.logger.Errorw(ctx, "failed to create activation token", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}

		// Send activation email to the user
		if err := u.messager.PublishPasswordResetEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
			// Log error if email sending failed
			u.logger.Errorw(ctx, "failed to send activation email", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	} else {
		// Generate a new activation token for phone-based password reset
		tokenId, token, err := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_ACTIVATION_PHONE, userData.Id)
		if err != nil || tokenId == 0 || token == "" {
			// Log error if token generation failed
			u.logger.Errorw(ctx, "failed to create activation token", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}

		// Send activation SMS to the user
		if err := u.messager.PublishPasswordResetPhone(userData.Phone, userData.Name, token); err != nil {
			// Log error if SMS sending failed
			u.logger.Errorw(ctx, "failed to send activation SMS", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	}

	// Log the successful password reset request
	u.logger.Infow(ctx, "password reset request sent successfully", "event", "user_forgot_password_success", "userId", userData.Id)
	return domain.UserForgotPasswordClientResponse{Message: "Password reset request sent successfully"}, domain.ErrorRes{}
}

// ResetPassword handles the user request to reset their password after receiving a token.
func (u *userusecase) ResetPassword(ctx context.Context, req domain.UserResetPasswordClientRequest) (domain.UserResetPasswordClientResponse, domain.ErrorRes) {
	var (
		userData  *domain.User
		errRes    domain.ErrorRes
		tokenType int8
	)

	userData, errRes = u.fetchUser(ctx, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	if req.Email != "" {
		tokenType = constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL
	} else if req.Phone != "" {
		tokenType = constant.TOKEN_TYPE_PASSWORD_RESET_PHONE
	}

	// Fetch and validate the activation token
	tokenData, errRes := u.validateUserToken(ctx, tokenType, req.Token, userData.Id)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Update the user's password
	errRes = u.updateUserPassword(ctx, userData, req.Password)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Revoke the activation token after successful password reset
	if err := u.mysql.RevokeToken(ctx, tokenData.Id); err != nil {
		// Log error if token revocation failed
		u.logger.Errorw(ctx, "failed to revoke activation token", "userId", userData.Id, "error", err)
		return domain.UserResetPasswordClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}

	// Log the successful password reset
	u.logger.Infow(ctx, "user password reset successful", "event", "user_reset_password_success", "userId", userData.Id)
	return domain.UserResetPasswordClientResponse{Message: "Password has been reset successfully"}, domain.ErrorRes{}
}

// updateUserPassword hashes and updates the user's password in the database.
func (u *userusecase) updateUserPassword(ctx context.Context, userData *domain.User, password string) domain.ErrorRes {
	// Hash the new password using bcrypt
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+userData.Salt), u.conf.GetPasswordHashCost())
	if err != nil {
		// Log error if password hashing failed
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

	// Update the password in the database
	err = u.mysql.UpdatePassword(ctx, userData.Id, string(hashPassword))
	if err != nil {
		// Log error if updating the password failed
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

	// Return no errors if password update is successful
	return domain.ErrorRes{}
}

// generatePasswordResetToken revokes old tokens and creates a new one for password reset.
func (u *userusecase) generatePasswordResetToken(ctx context.Context, tokenType int8, userID int) (int, string, error) {
	// Revoke all previous tokens for the user
	if err := u.mysql.RevokeAllTokens(ctx, tokenType, userID); err != nil {
		// Log error if revoking old tokens failed
		u.logger.Errorw(ctx, "failed to revoke old tokens",
			"event", "revoke_tokens_failed",
			"userID", userID,
			"tokenType", tokenType,
			"error", err,
		)
		return 0, "", err
	}

	// Generate a new token for password reset
	activationToken := utils.GenerateRandomString(25)

	// Store the new token in the database
	tokenData := domain.UserTokens{
		UserId:    userID,
		Token:     activationToken,
		Type:      tokenType,
		ExpiresAt: u.getPasswordResetTokenExpiry(),
	}

	// Save the token to the database and return the token ID and value
	tokenId, err := u.mysql.CreateToken(ctx, tokenData)
	if err != nil {
		// Log error if storing the new token failed
		u.logger.Errorw(ctx, "failed to store password reset token",
			"event", "create_token_failed",
			"userID", userID,
			"error", err,
		)
		return 0, "", err
	}

	// Return the generated token and its ID
	return tokenId, activationToken, nil
}
