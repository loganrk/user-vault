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

func (u *userusecase) Register(ctx context.Context, req domain.UserRegisterClientRequest) (domain.UserRegisterClientResponse, domain.ErrorRes) {
	if errRes := u.checkUserDoesNotExist(ctx, req.Email, req.Phone); errRes.Code != 0 {
		return domain.UserRegisterClientResponse{}, errRes
	}

	userId, errRes := u.createUser(ctx, req)
	if errRes.Code != 0 {
		return domain.UserRegisterClientResponse{}, errRes
	}

	userData, errRes := u.fetchUserByID(ctx, userId)
	if errRes.Code != 0 {
		return domain.UserRegisterClientResponse{}, errRes
	}

	if userData.Status == constant.USER_STATUS_PENDING {

		// Send the activation token to the user's email or phone
		if req.Email != "" {
			// Generate a new activation token for the user
			tokenId, token, err := u.generateActivationToken(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, userData.Id)
			if err != nil || tokenId == 0 || token == "" {
				u.logger.Errorw(ctx, "failed to create activation token", "userId", userData.Id, "error", err)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}

			// Send activation email
			if err := u.messager.PublishActivationEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
				u.logger.Errorw(ctx, "failed to send activation email", "userId", userData.Id, "error", err)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}
		} else {

			tokenId, token, err := u.generateActivationToken(ctx, constant.TOKEN_TYPE_ACTIVATION_PHONE, userData.Id)
			if err != nil || tokenId == 0 || token == "" {
				u.logger.Errorw(ctx, "failed to create activation token", "userId", userData.Id, "error", err)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}

			// Send activation SMS
			if err := u.messager.PublishActivationPhone(userData.Phone, userData.Name, token); err != nil {
				u.logger.Errorw(ctx, "failed to send activation SMS", "userId", userData.Id, "error", err)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}
		}

	}

	u.logger.Infow(ctx, "user registered successfully",
		"event", "register_success",
		"userId", userData.Id,
	)

	return domain.UserRegisterClientResponse{
		Message: "Account created successfully.",
	}, domain.ErrorRes{}
}

// ActivateUser handles the user account activation process by validating the token and updating the user status.
func (u *userusecase) ActivateUser(ctx context.Context, req domain.UserActivationClientRequest) (domain.UserActivationClientResponse, domain.ErrorRes) {
	var (
		userData  *domain.User
		errRes    domain.ErrorRes
		tokenType int8
	)

	// Check if email or phone is provided and fetch user data accordingly
	switch {
	case req.Email != "":
		userData, errRes = u.fetchUserByEmail(ctx, req.Email)
		tokenType = constant.TOKEN_TYPE_ACTIVATION_EMAIL
	case req.Phone != "":
		userData, errRes = u.fetchUserByPhone(ctx, req.Phone)
		tokenType = constant.TOKEN_TYPE_ACTIVATION_PHONE
	default:
		// Return error if neither email nor phone is provided
		return domain.UserActivationClientResponse{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Either email or phone is required",
		}
	}

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserActivationClientResponse{}, errRes
	}

	// Check if the account is in pending state before activation
	isPending, errRes := u.checkAccountIsPending(ctx, userData)
	if !isPending {
		return domain.UserActivationClientResponse{}, errRes
	}

	// Fetch and validate the activation token
	tokenData, errRes := u.fetchAndValidateActivationToken(ctx, tokenType, req.Token, userData.Id)
	if errRes.Code != 0 {
		return domain.UserActivationClientResponse{}, errRes
	}

	// Update user status to active
	if err := u.mysql.UpdateUserStatus(ctx, userData.Id, constant.USER_STATUS_ACTIVE); err != nil {
		u.logger.Errorw(ctx, "failed to activate user", "userId", userData.Id, "error", err)
		return domain.UserActivationClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	// Revoke the activation token after successful activation
	if err := u.mysql.RevokeToken(ctx, tokenData.Id); err != nil {
		u.logger.Errorw(ctx, "failed to revoke activation token", "userId", userData.Id, "error", err)
		return domain.UserActivationClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}

	// Log the successful user activation
	u.logger.Infow(ctx, "user activated", "userId", userData.Id)

	// Return successful activation response
	return domain.UserActivationClientResponse{
		Message: "Account has been activated successfully",
	}, domain.ErrorRes{}
}

// ResendActivation handles the process of resending an activation token to the user's email or phone.
func (u *userusecase) ResendActivation(ctx context.Context, req domain.UserResendActivationClientRequest) (domain.UserResendActivationClientResponse, domain.ErrorRes) {
	var (
		userData  *domain.User
		errRes    domain.ErrorRes
		tokenType int8
	)

	// Check if email or phone is provided and fetch user data accordingly
	switch {
	case req.Email != "":
		userData, errRes = u.fetchUserByEmail(ctx, req.Email)
		tokenType = constant.TOKEN_TYPE_ACTIVATION_EMAIL
	case req.Phone != "":
		userData, errRes = u.fetchUserByPhone(ctx, req.Phone)
		tokenType = constant.TOKEN_TYPE_ACTIVATION_PHONE
	default:
		// Return error if neither email nor phone is provided
		return domain.UserResendActivationClientResponse{}, domain.ErrorRes{
			Code:    http.StatusBadRequest,
			Message: "Either email or phone is required",
		}
	}

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		return domain.UserResendActivationClientResponse{}, errRes
	}

	// Check if the account is in pending state before resending activation token
	isPending, errRes := u.checkAccountIsPending(ctx, userData)
	if !isPending {
		return domain.UserResendActivationClientResponse{}, errRes
	}

	// Generate a new activation token for the user
	tokenId, token, err := u.generateActivationToken(ctx, tokenType, userData.Id)
	if err != nil || tokenId == 0 || token == "" {
		u.logger.Errorw(ctx, "failed to create activation token", "userId", userData.Id, "error", err)
		return domain.UserResendActivationClientResponse{}, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	// Send the activation token to the user's email or phone
	if req.Email != "" {
		// Send activation email
		if err := u.messager.PublishActivationEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "failed to send activation email", "userId", userData.Id, "error", err)
			return domain.UserResendActivationClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	} else {
		// Send activation SMS
		if err := u.messager.PublishActivationPhone(userData.Phone, userData.Name, token); err != nil {
			u.logger.Errorw(ctx, "failed to send activation SMS", "userId", userData.Id, "error", err)
			return domain.UserResendActivationClientResponse{}, domain.ErrorRes{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
				Err:     err,
			}
		}
	}

	// Log the successful resend of activation message
	u.logger.Infow(ctx, "activation message resent", "userId", userData.Id)

	// Return success message with channel (email/phone) information
	return domain.UserResendActivationClientResponse{
		Message: "Please check your " + func() string {
			if req.Email != "" {
				return "email"
			}
			return "phone"
		}() + " to activate your account",
	}, domain.ErrorRes{}
}

func (u *userusecase) checkUserDoesNotExist(ctx context.Context, email, phone string) domain.ErrorRes {
	existingUser, err := u.mysql.GetUserByEmailOrPhone(ctx, email, phone)
	if err != nil {
		u.logger.Errorw(ctx, "failed to check if username exists",
			"event", "register_failed",
			"email", email,
			"phone", phone,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	if existingUser.Id != 0 {
		u.logger.Warnw(ctx, "username already exists",
			"event", "register_failed",
			"email", email,
			"phone", phone,
			"code", http.StatusConflict,
		)
		return domain.ErrorRes{
			Code:    http.StatusConflict,
			Message: "Username already exists",
		}
	}
	return domain.ErrorRes{}
}

func (u *userusecase) createUser(ctx context.Context, req domain.UserRegisterClientRequest) (int, domain.ErrorRes) {
	saltHash, err := utils.NewSaltHash()
	if err != nil {
		u.logger.Errorw(ctx, "failed to generate salt hash", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		u.logger.Errorw(ctx, "failed to hash password", "event", "register_failed", "error", err)
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
		Salt:     saltHash,
		Name:     req.Name,
		State:    constant.USER_STATE_INITIAL,
		Status:   constant.USER_STATUS_PENDING,
	}

	userID, err := u.mysql.CreateUser(ctx, userData)
	if err != nil {
		u.logger.Errorw(ctx, "failed to create new user", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	return userID, domain.ErrorRes{}
}

func (u *userusecase) createUserForOAuth(ctx context.Context, email, name string) (int, domain.ErrorRes) {
	saltHash, err := utils.NewSaltHash()
	if err != nil {
		u.logger.Errorw(ctx, "failed to generate salt hash", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	userData := domain.User{
		Email:  email,
		Salt:   saltHash,
		Name:   name,
		State:  constant.USER_STATE_INITIAL,
		Status: constant.USER_STATUS_ACTIVE,
	}

	userID, err := u.mysql.CreateUser(ctx, userData)
	if err != nil {
		u.logger.Errorw(ctx, "failed to create new user", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	return userID, domain.ErrorRes{}
}

// fetchAndValidateActivationToken retrieves and validates activation token for the user.
func (u *userusecase) fetchAndValidateActivationToken(ctx context.Context, tokenType int8, token string, userID int) (*domain.UserTokens, domain.ErrorRes) {
	tokenData, err := u.mysql.GetUserLastTokenByUserId(ctx, tokenType, userID)
	if err != nil || tokenData.Id == 0 {
		u.logger.Errorw(ctx, "invalid or expired token", "token", token, "error", err)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Invalid or expired token", Err: err}
	}

	// Validate token properties such as mismatch, already used, or expired
	if tokenData.Token != token {
		u.logger.Warnw(ctx, "token mismatch", "token", token)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Invalid activation token"}
	}

	if tokenData.Revoked {
		u.logger.Warnw(ctx, "token already used", "token", token)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Activation token already used"}
	}

	if tokenData.ExpiresAt.Before(time.Now()) {
		u.logger.Warnw(ctx, "token expired", "token", token)
		return nil, domain.ErrorRes{Code: http.StatusBadRequest, Message: "Activation token expired"}
	}

	return &tokenData, domain.ErrorRes{}
}

// createActivationToken generates a new activation token and stores it in the DB.
func (u *userusecase) generateActivationToken(ctx context.Context, tokenType int8, userID int) (int, string, error) {
	activationToken := utils.GenerateRandomString(25)

	// TODO: Revoke all existing tokens of same type for userID

	// Create token data object
	tokenData := domain.UserTokens{
		UserId:    userID,
		Token:     activationToken,
		Type:      tokenType,
		ExpiresAt: u.getActivationTokenExpiry(),
	}

	// Store the generated token in DB
	tokenId, err := u.mysql.CreateToken(ctx, tokenData)
	if err != nil {
		return 0, "", err
	}

	return tokenId, activationToken, nil
}
