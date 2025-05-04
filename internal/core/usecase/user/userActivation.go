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
	// Check if user already exists by email or phone
	if errRes := u.checkUserDoesNotExist(ctx, req.Email, req.Phone); errRes.Code != 0 {
		u.logger.Warnw(ctx, "user already exists",
			"email", req.Email,
			"phone", req.Phone,
			"error", errRes.Message,
		)
		return domain.UserRegisterClientResponse{}, errRes
	}

	// Create a new user in the system
	userId, errRes := u.createUser(ctx, req)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "failed to create user",
			"email", req.Email,
			"phone", req.Phone,
			"error", errRes.Message,
		)
		return domain.UserRegisterClientResponse{}, errRes
	}

	// Fetch user data by user ID
	userData, errRes := u.fetchUserByID(ctx, userId)
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "failed to fetch user data",
			"userId", userId,
			"error", errRes.Message,
		)
		return domain.UserRegisterClientResponse{}, errRes
	}

	// If the user's account is pending, send the activation token to email or phone
	if userData.Status == constant.USER_STATUS_PENDING {
		// If email is provided, send activation email
		if req.Email != "" {
			tokenId, token, err := u.generateActivationToken(ctx, constant.TOKEN_TYPE_ACTIVATION_EMAIL, userData.Id)
			if err != nil || tokenId == 0 || token == "" {
				u.logger.Errorw(ctx, "failed to create activation token",
					"userId", userData.Id,
					"error", err,
				)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}

			// Send activation email
			if err := u.messager.PublishActivationEmail(userData.Email, constant.USER_ACTIVATION_EMAIL_SUBJECT, userData.Name, token); err != nil {
				u.logger.Errorw(ctx, "failed to send activation email",
					"userId", userData.Id,
					"email", userData.Email,
					"error", err,
				)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}
		} else { // If email is not provided, send activation SMS
			tokenId, token, err := u.generateActivationToken(ctx, constant.TOKEN_TYPE_ACTIVATION_PHONE, userData.Id)
			if err != nil || tokenId == 0 || token == "" {
				u.logger.Errorw(ctx, "failed to create activation token",
					"userId", userData.Id,
					"error", err,
				)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}

			// Send activation SMS
			if err := u.messager.PublishActivationPhone(userData.Phone, userData.Name, token); err != nil {
				u.logger.Errorw(ctx, "failed to send activation SMS",
					"userId", userData.Id,
					"phone", userData.Phone,
					"error", err,
				)
				return domain.UserRegisterClientResponse{}, domain.ErrorRes{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Err:     err,
				}
			}
		}
	}

	// Log user registration success
	u.logger.Infow(ctx, "user registered successfully",
		"event", "register_success",
		"userId", userData.Id,
		"email", userData.Email,
	)

	// Return success message
	return domain.UserRegisterClientResponse{
		Message: "Account created successfully.",
	}, domain.ErrorRes{}
}

// ActivateUser handles the user account activation process.
func (u *userusecase) ActivateUser(ctx context.Context, req domain.UserActivationClientRequest) (domain.UserActivationClientResponse, domain.ErrorRes) {
	var (
		userData *domain.User
		errRes   domain.ErrorRes
	)
	userData, errRes = u.fetchUser(ctx, req.Email, req.Phone)

	// Log errors in case of failure to fetch user data
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "failed to fetch user data",
			"email", req.Email,
			"phone", req.Phone,
			"error", errRes.Message,
		)
		return domain.UserActivationClientResponse{}, errRes
	}

	// Activate user account and log the result
	if userData.Status == constant.USER_STATUS_PENDING {
		// Perform activation logic
		u.logger.Infow(ctx, "user account activated",
			"userId", userData.Id,
			"email", userData.Email,
		)
	} else {
		u.logger.Warnw(ctx, "user already activated",
			"userId", userData.Id,
			"status", userData.Status,
		)
	}

	// Return activation success
	return domain.UserActivationClientResponse{
		Message: "User account activated successfully.",
	}, domain.ErrorRes{}
}

// ResendActivation handles the process of resending an activation token to the user's email or phone.
func (u *userusecase) ResendActivation(ctx context.Context, req domain.UserResendActivationClientRequest) (domain.UserResendActivationClientResponse, domain.ErrorRes) {
	var (
		userData  *domain.User
		errRes    domain.ErrorRes
		tokenType int8
	)
	userData, errRes = u.fetchUser(ctx, req.Email, req.Phone)

	// Return if there was an error fetching user data
	if errRes.Code != 0 {
		u.logger.Errorw(ctx, "failed to fetch user data", "error", errRes.Message, "email", req.Email, "phone", req.Phone)
		return domain.UserResendActivationClientResponse{}, errRes
	}

	// Check if the account is in pending state before resending activation token
	isPending, errRes := u.checkAccountIsPending(ctx, userData)
	if !isPending {
		u.logger.Warnw(ctx, "account not pending, cannot resend activation", "userId", userData.Id, "state", userData.State)
		return domain.UserResendActivationClientResponse{}, errRes
	}

	if req.Email != "" {
		tokenType = constant.TOKEN_TYPE_PASSWORD_RESET_EMAIL
	} else if req.Phone != "" {
		tokenType = constant.TOKEN_TYPE_PASSWORD_RESET_PHONE
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
	u.logger.Infow(ctx, "activation message resent", "userId", userData.Id, "channel", func() string {
		if req.Email != "" {
			return "email"
		}
		return "phone"
	}())

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

// checkUserDoesNotExist checks if a user already exists with the provided email or phone.
func (u *userusecase) checkUserDoesNotExist(ctx context.Context, email, phone string) domain.ErrorRes {
	existingUser, err := u.mysql.GetUserByEmailOrPhone(ctx, email, phone)
	if err != nil {
		u.logger.Errorw(ctx, "failed to check if user exists", "event", "register_failed", "email", email, "phone", phone, "error", err)
		return domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	if existingUser.Id != 0 {
		u.logger.Warnw(ctx, "user already exists", "event", "register_failed", "email", email, "phone", phone)
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

// createUserForOAuth creates a new user for OAuth.
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
		u.logger.Errorw(ctx, "failed to create new user for OAuth", "event", "register_failed", "error", err)
		return 0, domain.ErrorRes{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
			Err:     err,
		}
	}

	return userID, domain.ErrorRes{}
}

// generateActivationToken generates a new activation token and stores it in the DB.
func (u *userusecase) generateActivationToken(ctx context.Context, tokenType int8, userID int) (int, string, error) {

	err := u.mysql.RevokeAllTokens(ctx, tokenType, userID)
	if err != nil {
		return 0, "", err

	}

	activationToken := utils.GenerateRandomString(25)

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
