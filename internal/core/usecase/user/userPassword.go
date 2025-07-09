package user

import (
	"context"
	"net/http"
	"strings"

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
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "fetch_user failed", "email", req.Email, "phone", req.Phone, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}

		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneVerified(userData, req.Email, req.Phone)
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, errRes.Message, "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	// Check if the account is active
	errRes = u.checkAccountIsActive(ctx, userData)
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, errRes.Message, "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		return domain.UserForgotPasswordClientResponse{}, errRes
	}

	// Generate and send the verification token to the user's email or phone
	if req.Email != "" {
		// Generate a new verification token for email-based password reset
		_, token, errRes := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL, userData.Id)
		if errRes.Code != 0 {
			u.logger.Errorw(ctx, errRes.Message, "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
			return domain.UserForgotPasswordClientResponse{}, errRes
		}

		// Send verification email to the user
		link := strings.Replace(u.conf.GetPasswordResetLink(), constant.TOKEN_MACRO, token, 1)
		if err := u.messager.PublishPasswordResetEmail(userData.Email, constant.USER_PASSWORD_RESET_EMAIL_SUBJECT, userData.Name, link); err != nil {
			u.logger.Errorw(ctx, "failed to send verification email", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       err.Error(),
				Exception: constant.NetworkException,
			}
		}
	} else {
		// Generate a new verification token for phone-based password reset
		_, token, errRes := u.generatePasswordResetToken(ctx, constant.TOKEN_TYPE_PASSWORD_RESET_PHONE, userData.Id)
		if errRes.Code != 0 {
			u.logger.Errorw(ctx, errRes.Message, "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
			return domain.UserForgotPasswordClientResponse{}, errRes
		}

		// Send verification SMS to the user
		if err := u.messager.PublishPasswordResetPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "failed to send verification sms", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
			return domain.UserForgotPasswordClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       "failed to send verification sms" + err.Error(),
				Exception: constant.NetworkException,
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
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "fetch_user failed", "email", req.Email, "phone", req.Phone, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneVerified(userData, req.Email, req.Phone)
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

	// Fetch and validate the verification token
	tokenData, errRes := u.validateUserToken(ctx, tokenType, req.Token, userData.Id)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "validate_user_token failed", "userId", userData.Id, "tokenType", tokenType, "token", req.Token, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	userPassword, err := u.mysql.GetUserPasswordByUserID(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "get_user_password_by_user_id failed", "userId", userData.Id, "error", err.Error(), "exception", constant.DBException)
		return domain.UserResetPasswordClientResponse{}, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       err.Error(),
			Exception: constant.DBException,
		}
	}

	// Update the user's password
	errRes = u.updateUserPassword(ctx, userData, userPassword.Salt, req.Password)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "update_user_password failed", "userId", userData.Id, "error", errRes.Err, "exception", errRes.Exception)
		return domain.UserResetPasswordClientResponse{}, errRes
	}

	// Revoke the verification token after successful password reset
	if err := u.mysql.RevokeToken(ctx, tokenData.Id); err != nil {
		u.logger.Errorw(ctx, "revoke_token failed", "tokenId", tokenData.Id, "error", err.Error(), "exception", constant.DBException)
		return domain.UserResetPasswordClientResponse{}, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       err.Error(),
			Exception: constant.DBException,
		}
	}

	return domain.UserResetPasswordClientResponse{Message: "Password has been reset successfully"}, domain.ErrorRes{}
}

// updateUserPassword hashes and updates the user's password in the database.
func (u *userusecase) updateUserPassword(ctx context.Context, userData *domain.User, salt string, password string) domain.ErrorRes {
	// Hash the new password using bcrypt
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt), u.conf.GetPasswordHashCost())
	if err != nil {
		return domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create the hash password. error = " + err.Error(),
			Exception: constant.GenericException,
		}
	}

	// Update the password in the database
	err = u.mysql.UpdatePassword(ctx, userData.Id, string(hashPassword))
	if err != nil {
		return domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to update the user password. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	return domain.ErrorRes{}
}

// generatePasswordResetToken revokes old tokens and creates a new one for password reset.
func (u *userusecase) generatePasswordResetToken(ctx context.Context, tokenType int8, userID int) (int, string, domain.ErrorRes) {
	// Revoke all previous tokens for the user
	if err := u.mysql.RevokeAllTokens(ctx, tokenType, userID); err != nil {
		return 0, "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to revoke old tokens. error = " + err.Error(),
			Exception: constant.DBException,
		}
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
		return 0, "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create new token. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	return tokenId, verificationToken, domain.ErrorRes{}
}
