package user

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// Register handles the user registration process.
func (u *userusecase) Register(ctx context.Context, req domain.UserRegisterClientRequest) (domain.UserRegisterClientResponse, domain.ErrorRes) {

	if errRes := u.checkUserDoesNotExist(ctx, req.Email, req.Phone); errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "check_user_does_not_exists failed", "email", req.Email, "phone", req.Phone, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserRegisterClientResponse{}, errRes
	}

	userId, errRes := u.createUser(ctx, req)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "create_user failed", "email", req.Email, "phone", req.Phone, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		return domain.UserRegisterClientResponse{}, errRes
	}

	userData, errRes := u.fetchUserByID(ctx, userId)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "fetch_user_by_id failed", "userId", userData.Id, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserRegisterClientResponse{}, errRes
	}

	var tokenType int8
	if req.Email != "" {
		tokenType = constant.TOKEN_TYPE_ACTIVATION_EMAIL
	} else {
		tokenType = constant.TOKEN_TYPE_ACTIVATION_PHONE
	}

	token, errRes := u.generateVerificationToken(ctx, tokenType, userData.Id)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "generate_verification_token failed", "userId", userData.Id, "tokenType", tokenType, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserRegisterClientResponse{}, errRes
	}

	if tokenType == constant.TOKEN_TYPE_ACTIVATION_EMAIL {
		link := strings.Replace(token, constant.TOKEN_MACRO, u.conf.GetVerificationLink(), 1)
		if err := u.messager.PublishVerificationEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, link); err != nil {
			u.logger.Errorw(ctx, "publish_verification_email failed", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
			return domain.UserRegisterClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       err.Error(),
				Exception: constant.NetworkException,
			}
		}

	} else {
		if err := u.messager.PublishVerificationPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "publish_verification_phone failed", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
			return domain.UserRegisterClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       err.Error(),
				Exception: constant.NetworkException,
			}
		}
	}

	return domain.UserRegisterClientResponse{Message: "Account created successfully."}, domain.ErrorRes{}
}

// VerifyUser handles the user account verification process.
func (u *userusecase) VerifyUser(ctx context.Context, req domain.UserVerifyClientRequest) (domain.UserVerifyClientResponse, domain.ErrorRes) {
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
		return domain.UserVerifyClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneNotVerified(userData, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserVerifyClientResponse{}, errRes
	}

	if req.Email != "" {
		tokenType = constant.TOKEN_TYPE_ACTIVATION_EMAIL
	} else {
		tokenType = constant.TOKEN_TYPE_ACTIVATION_PHONE
	}

	// Fetch and validate the verification token
	tokenData, errRes := u.validateUserToken(ctx, tokenType, req.Token, userData.Id)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "validate_user_token failed", "userId", userData.Id, "tokenType", tokenType, "token", req.Token, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserVerifyClientResponse{}, errRes
	}

	if tokenType == constant.TOKEN_TYPE_ACTIVATION_EMAIL {

		if err := u.mysql.UpdateEmailVerfied(ctx, userData.Id); err != nil {
			u.logger.Errorw(ctx, "update_email_verfied failed", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.DBException)
			return domain.UserVerifyClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       err.Error(),
				Exception: constant.DBException,
			}
		}
	} else {

		if err := u.mysql.UpdatePhoneVerfied(ctx, userData.Id); err != nil {
			u.logger.Errorw(ctx, "update_phone_verfied failed", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.DBException)
			return domain.UserVerifyClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       err.Error(),
				Exception: constant.DBException,
			}
		}
	}

	// Revoke the verification token after successful password reset
	if err := u.mysql.RevokeToken(ctx, tokenData.Id); err != nil {
		u.logger.Errorw(ctx, "revoke_token failed", "tokenId", tokenData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.DBException)
		return domain.UserVerifyClientResponse{}, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       err.Error(),
			Exception: constant.DBException,
		}
	}

	return domain.UserVerifyClientResponse{Message: "User account activated successfully."}, domain.ErrorRes{}
}

// ResendVerification handles the process of resending an verification token to the user's email or phone.
func (u *userusecase) ResendVerification(ctx context.Context, req domain.UserResendVerificationClientRequest) (domain.UserResendVerificationClientResponse, domain.ErrorRes) {
	userData, errRes := u.fetchUser(ctx, req.Email, req.Phone)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "fetch_user failed", "email", req.Email, "phone", req.Phone, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserResendVerificationClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneNotVerified(userData, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserResendVerificationClientResponse{}, errRes
	}

	tokenType := constant.TOKEN_TYPE_ACTIVATION_EMAIL
	if req.Phone != "" {
		tokenType = constant.TOKEN_TYPE_ACTIVATION_PHONE
	}

	token, errRes := u.generateVerificationToken(ctx, tokenType, userData.Id)
	if errRes.Code != 0 {
		if errRes.Err != "" {
			u.logger.Errorw(ctx, "generate_verification_token failed", "userId", userData.Id, "tokenType", tokenType, "error", errRes.Err, "code", errRes.Code, "exception", errRes.Exception)
		}
		return domain.UserResendVerificationClientResponse{}, errRes
	}

	if req.Email != "" {
		link := strings.Replace(token, constant.TOKEN_MACRO, u.conf.GetPasswordResetLink(), 1)
		fmt.Println("link")
		if err := u.messager.PublishVerificationEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, link); err != nil {
			u.logger.Errorw(ctx, "publish_verification_email failed", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
			return domain.UserResendVerificationClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       err.Error(),
				Exception: constant.NetworkException,
			}
		}
	} else {
		if err := u.messager.PublishVerificationPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "publish_verification_phone failed", "userId", userData.Id, "error", err.Error(), "code", http.StatusInternalServerError, "exception", constant.NetworkException)
			return domain.UserResendVerificationClientResponse{}, domain.ErrorRes{
				Code:      http.StatusInternalServerError,
				Message:   constant.MessageInternalServerError,
				Err:       err.Error(),
				Exception: constant.NetworkException,
			}
		}
	}

	return domain.UserResendVerificationClientResponse{Message: "Activation Send Succefully.Please activate your account"}, domain.ErrorRes{}
}

// checkUserDoesNotExist checks if a user already exists with the provided email or phone.
func (u *userusecase) checkUserDoesNotExist(ctx context.Context, email, phone string) domain.ErrorRes {
	existingUser, err := u.mysql.GetUserByEmailOrPhone(ctx, email, phone)
	if err != nil {
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     "failed to retreive the user from email or phone. error = " + err.Error(),
		}
	}

	if existingUser.Id != 0 {
		u.logger.Warnw(ctx, "User already exists", "event", "register_failed", "email", email, "phone", phone)
		return domain.ErrorRes{
			Code:    http.StatusConflict,
			Message: "User already exists",
		}
	}
	return domain.ErrorRes{}
}

// createUser creates a new user.
func (u *userusecase) createUser(ctx context.Context, req domain.UserRegisterClientRequest) (int, domain.ErrorRes) {
	saltHash, err := utils.NewSaltHash()
	if err != nil {
		return 0, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to generate salt hash. error = " + err.Error(),
			Exception: constant.GenericException,
		}
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		return 0, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to hash password. error = " + err.Error(),
			Exception: constant.GenericException,
		}
	}

	userData := domain.User{
		Email:    req.Email,
		Phone:    req.Phone,
		Password: string(hashPassword),
		Salt:     saltHash,
		Name:     req.Name,
		State:    constant.USER_STATE_INITIAL,
		Status:   constant.USER_STATUS_ACTIVE,
	}

	userID, err := u.mysql.CreateUser(ctx, userData)
	if err != nil {
		return 0, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create user. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	return userID, domain.ErrorRes{}
}

// createUserForOAuth creates a new user for OAuth.
func (u *userusecase) createUserForOAuth(ctx context.Context, email, name string) (int, domain.ErrorRes) {
	saltHash, err := utils.NewSaltHash()
	if err != nil {
		return 0, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to generate salt hash. error = " + err.Error(),
			Exception: constant.GenericException,
		}
	}

	userData := domain.User{
		Email:         email,
		EmailVerified: true,
		Salt:          saltHash,
		Name:          name,
		State:         constant.USER_STATE_INITIAL,
		Status:        constant.USER_STATUS_ACTIVE,
	}

	userID, err := u.mysql.CreateUser(ctx, userData)
	if err != nil {
		return 0, domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create user for OAuth. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	return userID, domain.ErrorRes{}
}

// generateVerificationToken generates a new verification token and stores it in the DB.
func (u *userusecase) generateVerificationToken(ctx context.Context, tokenType int8, userID int) (string, domain.ErrorRes) {
	// Revoke all previous tokens of this type for the user
	err := u.mysql.RevokeAllTokens(ctx, tokenType, userID)
	if err != nil {
		return "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to revoke existing tokens. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	// Generate a random verification token
	verificationToken := utils.GenerateRandomString(25)

	// Prepare token data
	tokenData := domain.UserTokens{
		UserId:    userID,
		Token:     verificationToken,
		Type:      tokenType,
		ExpiresAt: u.getVerificationTokenExpiry(),
	}

	// Store the new token
	_, err = u.mysql.CreateToken(ctx, tokenData)
	if err != nil {
		return "", domain.ErrorRes{
			Code:      http.StatusInternalServerError,
			Message:   constant.MessageInternalServerError,
			Err:       "failed to create verification token. error = " + err.Error(),
			Exception: constant.DBException,
		}
	}

	return verificationToken, domain.ErrorRes{}
}
