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
		u.logger.Warnw(ctx, "User email or phone fetch failed", "event", "user_forgot_password_failed", "request", req, "error", errRes.Message, "code", errRes.Code)
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneVerified(userData, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "User email or phone verification failed", "event", "user_forgot_password_failed", "userId", userData.Id, "error", errRes.Message, "code", errRes.Code)
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "User account validation failed", "event", "user_forgot_password_failed", "userId", userData.Id, "error", errRes.Err)
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	// Generate and send the verification token to the user's email or phone
	if req.Email != "" {
		// Generate a new verification token for email-based password reset
		tokenId, token, err := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, userData.Id)
		if err != nil || tokenId == 0 || token == "" {
			u.logger.Errorw(ctx, "failed to create verification token", "event", "user_forgot_password_failed", "userId", userData.Id, "error", err, "tokenId", tokenId, "token", token)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}

		// Send verification email to the user
		if err := u.messager.PublishPasswordResetEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "failed to send verification email", "event", "user_forgot_password_failed", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	} else {
		// Generate a new verification token for phone-based password reset
		tokenId, token, err := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_PHONE, userData.Id)
		if err != nil || tokenId == 0 || token == "" {
			u.logger.Errorw(ctx, "failed to create verification token", "event", "user_forgot_password_failed", "userId", userData.Id, "error", err)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}

		// Send verification SMS to the user
		if err := u.messager.PublishPasswordResetPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "failed to send verification SMS", "event", "user_forgot_password_failed", "userId", userData.Id, "error", err)
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

	errRes = u.isEmailOrPhoneVerified(userData, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "User email or phone verification failed", "event", "user_reset_password_failed", "user", req, "error", errRes.Message, "code", errRes.Code)
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

	// Fetch and validate the verification token
	tokenData, errRes := u.validateUserToken(ctx, tokenType, req.Token, userData.Id)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	userPassword, err := u.mysql.GetUserPasswordByUserID(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "Unable to fetch the user password", "event", "user_reset_password_success", "userId", userData.Id, "error", err)
		return domain.UserResetPasswordClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	// Update the user's password
	errRes = u.updateUserPassword(ctx, userData, userPassword.Salt, req.Password)
	if errRes.Code != 0 {
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Revoke the verification token after successful password reset
	if err := u.mysql.RevokeToken(ctx, tokenData.Id); err != nil {
		u.logger.Errorw(ctx, "failed to revoke verification token", "event", "user_reset_password_success", "userId", userData.Id, "error", err)
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
func (u *userusecase) updateUserPassword(ctx context.Context, userData *domain.User, salt string, password string) domain.ErrorRes {
	// Hash the new password using bcrypt
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt), u.conf.GetPasswordHashCost())
	if err != nil {
		u.logger.Errorw(ctx, "password hashing failed", "event", "hashing_failed", "userID", userData.Id, "error", err, "code", http.StatusInternalServerError)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to reset password",
			Err:     err,
		}
	}

	// Update the password in the database
	err = u.mysql.UpdatePassword(ctx, userData.Id, string(hashPassword))
	if err != nil {
		u.logger.Errorw(ctx, "failed to update user password", "event", "update_password_failed", "userID", userData.Id, "error", err, "code", http.StatusInternalServerError)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update password",
			Err:     err,
		}
	}

	// One-liner success log for password update success
	u.logger.Infow(ctx, "password updated successfully", "event", "password_update_success", "userID", userData.Id)
	return domain.ErrorRes{}
}

// generatePasswordResetToken revokes old tokens and creates a new one for password reset.
func (u *userusecase) generatePasswordResetToken(ctx context.Context, tokenType int8, userID int) (int, string, error) {
	// Revoke all previous tokens for the user
	if err := u.mysql.RevokeAllTokens(ctx, tokenType, userID); err != nil {
		u.logger.Errorw(ctx, "failed to revoke old tokens", "event", "revoke_tokens_failed", "userID", userID, "tokenType", tokenType, "error", err)
		return 0, "", err
	}

	// Generate a new token for password reset
	verificationToken := utils.GenerateRandomString(25)

	// Store the new token in the database
	tokenData := domain.UserTokens{
		UserId:    userID,
		Token:     verificationToken,
		Type:      tokenType,
		ExpiresAt: u.getPasswordResetTokenExpiry(),
	}

	// Save the token to the database and return the token ID and value
	tokenId, err := u.mysql.CreateToken(ctx, tokenData)
	if err != nil {
		u.logger.Errorw(ctx, "failed to store password reset token", "event", "create_token_failed", "userID", userID, "error", err)
		return 0, "", err
	}

	u.logger.Infow(ctx, "password reset token generated successfully", "event", "token_generation_success", "userID", userID)
	return tokenId, verificationToken, nil
}
