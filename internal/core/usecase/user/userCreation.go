package user

import (
	"context"
	"net/http"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// Register handles the user registration process.
func (u *userusecase) Register(ctx context.Context, req domain.UserRegisterClientRequest) (domain.UserRegisterClientResponse, domain.ErrorRes) {

	if errRes := u.checkUserDoesNotExist(ctx, req.Email, req.Phone); errRes.Code != 0 {
		u.logger.Warnw(ctx, "User already exists", "email", req.Email, "phone", req.Phone, "error", errRes.Message)
		return domain.UserRegisterClientResponse{}, errRes
	}

	userId, errRes := u.createUser(ctx, req)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "Failed to create user", "email", req.Email, "phone", req.Phone, "error", errRes.Message)
		return domain.UserRegisterClientResponse{}, errRes
	}

	userData, errRes := u.fetchUserByID(ctx, userId)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "Failed to fetch user data", "userId", userId, "error", errRes.Message)
		return domain.UserRegisterClientResponse{}, errRes
	}
	var tokenType int8

	if req.Email != "" {
		tokenType = constant.TOKEN_TYPE_ACTIVATION_EMAIL
	} else {
		tokenType = constant.TOKEN_TYPE_ACTIVATION_PHONE
	}

	tokenId, token, err := u.generateVerificationToken(ctx, tokenType, userData.Id)
	if err != nil || tokenId == 0 || token == "" {
		u.logger.Errorw(ctx, "Failed to create verification token", "userId", userData.Id, "error", err)
		return domain.UserRegisterClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	if tokenType == constant.TOKEN_TYPE_ACTIVATION_EMAIL {
		if err := u.messager.PublishVerificationEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "Failed to send verification email", "userId", userData.Id, "email", userData.Email, "error", err)
			return domain.UserRegisterClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	} else {
		if err := u.messager.PublishVerificationPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "Failed to send verification SMS", "userId", userData.Id, "phone", userData.Phone, "error", err)
			return domain.UserRegisterClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	}

	u.logger.Infow(ctx, "User registered successfully", "event", "register_success", "userId", userData.Id, "email", userData.Email)
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
		return domain.UserVerifyClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneNotVerified(userData, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "User email or phone verification failed", "event", "verify_user_failed", "user", req, "error", errRes.Message, "code", errRes.Code)
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
		return domain.UserVerifyClientResponse{}, errRes
	}

	if tokenType == constant.TOKEN_TYPE_ACTIVATION_EMAIL {

		if err := u.mysql.UpdateEmailVerfied(ctx, userData.Id); err != nil {
			u.logger.Errorw(ctx, "Failed to update email verfied", "event", "verify_user_failed", "userId", userData.Id, "error", err.Error())
			return domain.UserVerifyClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Failed to verify email.",
			}
		}
	} else {

		if err := u.mysql.UpdatePhoneVerfied(ctx, userData.Id); err != nil {
			u.logger.Errorw(ctx, "Failed to update phone verfied", "event", "verify_user_failed", "userId", userData.Id, "error", err.Error())
			return domain.UserVerifyClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Failed to verify phone.",
			}
		}
	}

	// Revoke the verification token after successful password reset
	if err := u.mysql.RevokeToken(ctx, tokenData.Id); err != nil {
		u.logger.Errorw(ctx, "failed to revoke verification token", "event", "verify_user_failed", "userId", userData.Id, "error", err)
		return domain.UserVerifyClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}

	return domain.UserVerifyClientResponse{Message: "User account activated successfully."}, domain.ErrorRes{}
}

// ResendVerification handles the process of resending an verification token to the user's email or phone.
func (u *userusecase) ResendVerification(ctx context.Context, req domain.UserResendVerificationClientRequest) (domain.UserResendVerificationClientResponse, domain.ErrorRes) {
	userData, errRes := u.fetchUser(ctx, req.Email, req.Phone)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "Failed to fetch user data", "error", errRes.Message, "email", req.Email, "phone", req.Phone)
		return domain.UserResendVerificationClientResponse{}, errRes
	}

	errRes = u.isEmailOrPhoneNotVerified(userData, req.Email, req.Phone)
	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		u.logger.Warnw(ctx, "User email or phone verification failed", "event", "verify_user_failed", "user", req, "error", errRes.Message, "code", errRes.Code)
		return domain.UserResendVerificationClientResponse{}, errRes
	}

	tokenType := constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL
	if req.Phone != "" {
		tokenType = constant.TOKEN_TYPE_PASSWORD_RESET_PHONE
	}

	tokenId, token, err := u.generateVerificationToken(ctx, tokenType, userData.Id)
	if err != nil || tokenId == 0 || token == "" {
		u.logger.Errorw(ctx, "Failed to create verification token", "userId", userData.Id, "error", err)
		return domain.UserResendVerificationClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	if req.Email != "" {
		if err := u.messager.PublishVerificationEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "Failed to send verification email", "userId", userData.Id, "error", err)
			return domain.UserResendVerificationClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	} else {
		if err := u.messager.PublishVerificationPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "Failed to send verification SMS", "userId", userData.Id, "error", err)
			return domain.UserResendVerificationClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	}
	u.logger.Infow(ctx, "Verification message resent", "userId", userData.Id, "channel")
	return domain.UserResendVerificationClientResponse{Message: "Please activate your account"}, domain.ErrorRes{}
}

// checkUserDoesNotExist checks if a user already exists with the provided email or phone.
func (u *userusecase) checkUserDoesNotExist(ctx context.Context, email, phone string) domain.ErrorRes {
	existingUser, err := u.mysql.GetUserByEmailOrPhone(ctx, email, phone)
	if err != nil {
		u.logger.Errorw(ctx, "Failed to check if user exists", "event", "register_failed", "email", email, "phone", phone, "error", err)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
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
		u.logger.Errorw(ctx, "Failed to generate salt hash", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		u.logger.Errorw(ctx, "Failed to hash password", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}
	userData := domain.User{
		Email:    req.Email,
		Phone:    req.Phone,
		Password: string(hashPassword),
		Salt:     saltHash, Name: req.Name,
		State:  constant.USER_STATE_INITIAL,
		Status: constant.USER_STATUS_ACTIVE,
	}

	userID, err := u.mysql.CreateUser(ctx, userData)
	if err != nil {
		u.logger.Errorw(ctx, "Failed to create new user", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}
	return userID, domain.ErrorRes{}
}

// createUserForOAuth creates a new user for OAuth.
func (u *userusecase) createUserForOAuth(ctx context.Context, email, name string) (int, domain.ErrorRes) {
	saltHash, err := utils.NewSaltHash()
	if err != nil {
		u.logger.Errorw(ctx, "Failed to generate salt hash", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
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
		u.logger.Errorw(ctx, "Failed to create new user for OAuth", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err}
	}
	return userID, domain.ErrorRes{}
}

// generateVerificationToken generates a new verification token and stores it in the DB.
func (u *userusecase) generateVerificationToken(ctx context.Context, tokenType int8, userID int) (int, string, error) {
	err := u.mysql.RevokeAllTokens(ctx, tokenType, userID)
	if err != nil {
		return 0, "", err
	}
	verificationToken := utils.GenerateRandomString(25)
	tokenData := domain.UserTokens{UserId: userID, Token: verificationToken, Type: tokenType, ExpiresAt: u.getVerificationTokenExpiry()}
	tokenId, err := u.mysql.CreateToken(ctx, tokenData)
	if err != nil {
		return 0, "", err
	}
	return tokenId, verificationToken, nil
}
