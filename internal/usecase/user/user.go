package user

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
	"userVault/config"
	"userVault/internal/constant"
	"userVault/internal/domain"
	"userVault/internal/port"
	"userVault/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

// Constants for various macros used in user activation and password reset links
const (
	USER_ACTIVATION_TOKEN_ID_MACRO = "{{tokenId}}"
	USER_ACTIVATION_TOKEN_MACRO    = "{{token}}"
	USER_ACTIVATION_LINK_MACRO     = "{{link}}"
	USER_ACTIVATION_NAME_MACRO     = "{{name}}"
	USER_ACTIVATION_APP_NAME_MACRO = "{{appName}}"

	USER_PASSWORD_RESET_TOKEN_MACRO    = "{{token}}"
	USER_PASSWORD_RESET_LINK_MACRO     = "{{link}}"
	USER_PASSWORD_RESET_NAME_MACRO     = "{{name}}"
	USER_PASSWORD_RESET_APP_NAME_MACRO = "{{appName}}"
)

// userusecase struct holds the dependencies for the user service, including
// configuration, logger, MySQL repository, and token management.
type userusecase struct {
	appName string
	logger  port.Logger
	mysql   port.RepositoryMySQL
	conf    config.User
	token   port.Token
}

// New initializes a new user service with required dependencies and returns it.
func New(loggerIns port.Logger, tokenIns port.Token, mysqlIns port.RepositoryMySQL, appName string, userConfIns config.User) domain.UserSvr {
	return &userusecase{
		mysql:  mysqlIns,
		logger: loggerIns,
		conf:   userConfIns,
		token:  tokenIns,
	}
}

// errorRes is a custom error response type that includes a status code, message, and error.
type errorRes struct {
	Code    int
	Message string
	Err     error
}

// Error implements the error interface for errorRes.
func (e errorRes) Error() error {
	return e.Err
}

// StatusCode returns the HTTP status code associated with the error.
func (e errorRes) StatusCode() int {
	return e.Code
}

// MessageText returns the error message.
func (e errorRes) MessageText() string {
	return e.Message
}

// Login is the main handler for user login. It performs various checks such as verifying
// the username, password, login attempts, and whether the user is active. If all checks
// pass, it generates access and refresh tokens and returns them to the client.
func (u *userusecase) Login(ctx context.Context, req domain.UserLoginClientRequest) (domain.UserLoginClientResponse, domain.ResponseError) {
	// Retrieve user data by username
	userData, err := u.getUserByUsername(ctx, req.Username)
	if err != nil {
		u.logger.Errorw(ctx, "failed to retrieve user by username",
			"event", "user_login_fetch_failed",
			"username", req.Username,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if userData.Id == 0 {
		u.logger.Warnw(ctx, "user not found for login",
			"event", "user_login_user_not_found",
			"username", req.Username,
			"code", http.StatusUnauthorized,
		)

		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusUnauthorized,
			Message: "Username or password is incorrect",
			Err:     nil,
		}
	}

	// Check if the user has reached the maximum number of failed login attempts
	attemptStatus, err := u.checkLoginFailedAttemptLimitReached(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "error checking failed login attempts",
			"event", "login_attempt_check_failed",
			"userId", userData.Id,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if attemptStatus == constant.LOGIN_ATTEMPT_MAX_REACHED {
		u.logger.Warnw(ctx, "max login attempts reached",
			"event", "login_blocked",
			"userId", userData.Id,
			"code", http.StatusTooManyRequests,
		)
		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusTooManyRequests,
			Message: "Maximum login attempts reached. Please try again later.",
			Err:     nil,
		}
	}

	// Compare password
	passwordMatch, err := u.comparePassword(ctx, req.Password, userData.Password, userData.Salt)
	if err != nil {
		u.logger.Errorw(ctx, "error comparing password",
			"event", "password_compare_failed",
			"userId", userData.Id,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if !passwordMatch {
		_, _ = u.createLoginAttempt(ctx, userData.Id, false)
		u.logger.Warnw(ctx, "password did not match",
			"event", "password_mismatch",
			"userId", userData.Id,
			"code", http.StatusUnauthorized,
		)

		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusUnauthorized,
			Message: "Username or password is incorrect",
			Err:     nil,
		}
	}

	// Log successful login attempt
	_, err = u.createLoginAttempt(ctx, userData.Id, true)

	if err != nil {
		u.logger.Errorw(ctx, "failed to create the login attempt",
			"event", "login_attempt_create_failed",
			"userId", userData.Id,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	// Re-fetch full user info
	userData, err = u.getUserByUserID(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user data after login",
			"event", "fetch_user_by_id_failed",
			"userId", userData.Id,
			"error", err,
			"code", http.StatusInternalServerError,
		)
		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	// Check user is active
	if userData.Status != constant.USER_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "inactive user tried to login",
			"event", "inactive_user_login",
			"userId", userData.Id,
			"code", http.StatusForbidden,
		)
		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusForbidden,
			Message: "Your account is not active. Please contact support.",
			Err:     nil,
		}
	}

	// Generate access token
	accessToken, err := u.token.CreateAccessToken(userData.Id, userData.Username, userData.Name, u.getAccessTokenExpiry())
	if err != nil {
		u.logger.Errorw(ctx, "failed to create access token",
			"event", "access_token_generation_failed",
			"userId", userData.Id,
			"error", err,
			"code", http.StatusInternalServerError,
		)

		return domain.UserLoginClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	// Prepare refresh token if enabled
	var refreshToken, refreshTokenType string
	if u.refreshTokenEnabled() {
		if u.refreshTokenRotationEnabled() {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_ROTATING
		} else {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_STATIC
		}

		refreshTokenExpireAt := u.getRefreshTokenExpiry()
		refreshToken, err = u.token.CreateRefreshToken(userData.Id, refreshTokenExpireAt)
		if err != nil {
			u.logger.Errorw(ctx, "failed to create refresh token",
				"event", "refresh_token_generation_failed",
				"userId", userData.Id,
				"error", err,
				"code", http.StatusInternalServerError,
			)

			return domain.UserLoginClientResponse{}, errorRes{
				Code:    http.StatusInternalServerError,
				Message: "internal server error",
				Err:     err,
			}
		}

		_, err = u.createRefreshToken(ctx, userData.Id, refreshToken, refreshTokenExpireAt)
		if err != nil {
			u.logger.Errorw(ctx, "failed to store refresh token",
				"event", "refresh_token_storage_failed",
				"userId", userData.Id,
				"error", err,
				"code", http.StatusInternalServerError,
			)

			return domain.UserLoginClientResponse{}, errorRes{
				Code:    http.StatusInternalServerError,
				Message: "internal server error",
				Err:     err,
			}
		}
	}

	// Log successful login
	u.logger.Infow(ctx, "user login successful",
		"event", "user_login_success",
		"userId", userData.Id,
	)

	// Return tokens
	return domain.UserLoginClientResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshTokenType: refreshTokenType,
	}, nil
}

// Logout handles the user logout process, including the validation of the refresh token,
// revocation of the token, and logging of the logout event.
func (u *userusecase) Logout(ctx context.Context, req domain.UserLogoutClientRequest) (domain.UserLogoutClientResponse, domain.ResponseError) {

	// Retrieve refresh token data
	refreshData, err := u.getRefreshTokenData(ctx, req.RefreshToken)
	if err != nil {
		u.logger.Warnw(ctx, "failed to fetch refresh token data",
			"event", "user_refresh_token_fetch_failed",
			"refreshToken", req.RefreshToken,
			"error", err,
		)
		return domain.UserLogoutClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Invalid refresh token",
			Err:     err,
		}
	}

	// Validate token data
	if refreshData.Id == 0 || refreshData.Revoked {
		u.logger.Warnw(ctx, "revoked or invalid refresh token",
			"event", "user_refresh_token_invalid",
			"refreshToken", req.RefreshToken,
		)
		return domain.UserLogoutClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is revoked or incorrect",
			Err:     nil,
		}
	}

	//  Check token expiration
	if time.Now().After(refreshData.ExpiresAt) {
		u.logger.Warnw(ctx, "refresh token expired",
			"event", "refresh_token_expired",
			"refreshToken", req.RefreshToken,
		)
		return domain.UserLogoutClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is incorrect or expired",
			Err:     nil,
		}
	}

	//  Revoke the refresh token
	if err := u.RevokeRefreshToken(ctx, refreshData.UserId, req.RefreshToken); err != nil {
		u.logger.Errorw(ctx, "unable to revoke refresh token",
			"event", "logout_failed",
			"userId", refreshData.UserId,
			"refreshToken", req.RefreshToken,
			"error", err,
		)
		return domain.UserLogoutClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}

	//  Log success and return response
	u.logger.Infow(ctx, "user logged out successfully",
		"event", "logout_success",
		"userId", refreshData.UserId,
		"refreshToken", req.RefreshToken,
	)

	return domain.UserLogoutClientResponse{
		Message: "Logout successful",
	}, nil

}

// Register handles the user registration process, including the creation of a new user,
// password hashing, and sending an activation email if the user status is pending.
func (u *userusecase) Register(ctx context.Context, req domain.UserRegisterClientRequest) (domain.UserRegisterClientResponse, domain.ResponseError) {
	// Check if the username already exists in the system
	existingUser, err := u.getUserByUsername(ctx, req.Username)
	if err != nil {
		// Log error and return response indicating failure to check if username exists
		u.logger.Errorw(ctx, "failed to check if username exists",
			"event", "register_failed",
			"username", req.Username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to check if username exists",
			Err:     err,
		}
	}

	// If user already exists, return conflict error
	if existingUser.Id != 0 {
		u.logger.Warnw(ctx, "username already exists",
			"event", "register_failed",
			"username", req.Username,
		)
		return domain.UserRegisterClientResponse{}, errorRes{
			Code:    http.StatusConflict,
			Message: "Username already exists",
			Err:     nil,
		}
	}

	// Generate a new salt hash for password hashing
	saltHash, err := u.newSaltHash()
	if err != nil {
		// Log error and return response indicating failure to generate salt hash
		u.logger.Errorw(ctx, "failed to generate salt hash",
			"event", "register_failed",
			"username", req.Username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate salt hash",
			Err:     err,
		}
	}

	// Hash the user's password using bcrypt and the generated salt
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		// Log error and return response indicating failure to hash password
		u.logger.Errorw(ctx, "failed to hash password",
			"event", "register_failed",
			"username", req.Username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to hash password",
			Err:     err,
		}
	}

	// Prepare user data to be saved in the database
	var userData = domain.User{
		Username: req.Username,
		Password: string(hashPassword),
		Salt:     saltHash,
		Name:     req.Name,
		State:    constant.USER_STATE_INITIAL,
		Status:   constant.USER_STATUS_PENDING,
	}

	// Create a new user in the database
	userID, err := u.createUser(ctx, userData)
	if err != nil {
		// Log error and return response indicating failure to create user
		u.logger.Errorw(ctx, "failed to create new user",
			"event", "register_failed",
			"username", req.Username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create new user",
			Err:     err,
		}
	}

	// Retrieve the newly created user data to verify successful creation
	userData, err = u.getUserByUsername(ctx, req.Username)
	if err != nil {
		// Log error and return response indicating failure to fetch newly created user
		u.logger.Errorw(ctx, "failed to fetch newly created user",
			"event", "register_failed",
			"userId", userID,
			"error", err,
		)

		return domain.UserRegisterClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch newly created user",
			Err:     err,
		}
	}

	if userData.Id == 0 {
		u.logger.Errorw(ctx, "failed to fetch newly created user",
			"event", "register_failed",
			"userId", userID,
		)

		return domain.UserRegisterClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch newly created user",
			Err:     err,
		}
	}

	// If user status is pending, generate an activation token and send activation email
	if userData.Status == constant.USER_STATUS_PENDING {
		tokenID, activationToken, err := u.createActivationToken(ctx, userData.Id)
		if err != nil {
			// Log error and return response indicating failure to create activation token
			u.logger.Errorw(ctx, "failed to create activation token",
				"event", "register_failed",
				"userId", userData.Id,
				"error", err,
			)
			return domain.UserRegisterClientResponse{}, errorRes{
				Code:    http.StatusInternalServerError,
				Message: "Failed to create activation token",
				Err:     err,
			}
		}

		// If activation token is created successfully, send the activation email
		if tokenID != 0 && activationToken != "" {
			link := u.getActivationLink()
			link = u.activationLinkMacroReplacement(link, tokenID, activationToken)

			if link != "" {
				templatePath := u.conf.GetActivationEmailTemplate()

				template, err := utils.FindFileContent(templatePath)
				if err != nil {
					// Log error and return response indicating failure to load email template
					u.logger.Errorw(ctx, "failed to load email template",
						"event", "register_failed",
						"userId", userData.Id,
						"error", err,
					)
					return domain.UserRegisterClientResponse{}, errorRes{
						Code:    http.StatusInternalServerError,
						Message: "Failed to load email template",
						Err:     err,
					}
				}

				// Replace macros in the email template and send the activation email
				emailTemplate := u.activationTemplateMacroReplacement(template, userData.Name, link)

				if emailTemplate != "" {
					err = u.sendActivation(ctx, userData.Username, emailTemplate)
					if err != nil {
						// Log error and return response indicating failure to send activation email
						u.logger.Errorw(ctx, "failed to send activation email",
							"event", "register_failed",
							"userId", userData.Id,
							"error", err,
						)
						return domain.UserRegisterClientResponse{}, errorRes{
							Code:    http.StatusInternalServerError,
							Message: "Failed to send activation email",
							Err:     err,
						}
					}

					// Log successful user registration and email sending
					u.logger.Infow(ctx, "user registered successfully, activation email sent",
						"event", "register_success",
						"userId", userData.Id,
					)

					return domain.UserRegisterClientResponse{
						Message: "Account created successfully. Please check your email to activate your account.",
					}, nil
				}
			}
		}
	}

	// Log successful user registration
	u.logger.Infow(ctx, "user registered successfully",
		"event", "register_success",
		"userId", userData.Id,
	)

	// Return successful registration response
	return domain.UserRegisterClientResponse{
		Message: "Account created successfully.",
	}, nil
}

// ActivateUser activates the user account based on the provided activation token.
func (u *userusecase) ActivateUser(ctx context.Context, req domain.UserActivationClientRequest) (domain.UserActivationClientResponse, domain.ResponseError) {
	// Fetch the activation token data by token
	tokenData, err := u.getUserActivationByToken(ctx, req.Token)
	if err != nil {
		// Log error if token is invalid or expired
		u.logger.Errorw(ctx, "invalid or expired token",
			"event", "user_activation_failed",
			"token", req.Token,
			"error", err,
		)
		// Return response with error message
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Invalid or expired token",
			Err:     err,
		}
	}

	if tokenData.Id == 0 {
		u.logger.Errorw(ctx, "invalid or expired token",
			"event", "user_activation_failed",
			"token", req.Token,
		)
		// Return response with error message
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Invalid or expired token",
			Err:     err,
		}
	}

	// Check if the activation token is still active
	if tokenData.Status != constant.USER_ACTIVATION_TOKEN_STATUS_ACTIVE {
		// Log and return response if the token is already used
		u.logger.Warnw(ctx, "activation token already used",
			"event", "user_activation_failed",
			"token", req.Token,
		)
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Activation link already used",
			Err:     nil,
		}
	}

	// Check if the activation token has expired
	if tokenData.ExpiresAt.Before(time.Now()) {
		// Log and return response if the token has expired
		u.logger.Warnw(ctx, "activation link expired",
			"event", "user_activation_failed",
			"token", req.Token,
		)
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Activation link expired",
			Err:     nil,
		}
	}

	// Fetch user data based on the user ID from the token
	userData, err := u.getUserByUserID(ctx, tokenData.UserId)
	if err != nil {
		// Log error if unable to fetch user data
		u.logger.Errorw(ctx, "failed to fetch user data for activation",
			"event", "user_activation_failed",
			"token", req.Token,
			"userId", tokenData.UserId,
			"error", err,
		)
		// Return internal server error
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	// Handle different user statuses before activating the account
	if userData.Status != constant.USER_STATUS_PENDING {
		var message string
		// Determine message based on user status
		switch userData.Status {
		case constant.USER_STATUS_ACTIVE:
			message = "Account already active"
		case constant.USER_STATUS_INACTIVE:
			message = "Account is inactive"
		default:
			message = "Account is banned"
		}
		// Log and return response with the appropriate message based on status
		u.logger.Warnw(ctx, message,
			"event", "user_activation_failed",
			"userId", userData.Id,
		)
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: message,
			Err:     nil,
		}
	}

	// Update the activation token status to inactive
	err = u.UpdatedActivationStatus(ctx, tokenData.Id, constant.USER_ACTIVATION_TOKEN_STATUS_INACTIVE)
	if err != nil {
		// Log error if unable to update the token status
		u.logger.Errorw(ctx, "failed to update activation token status",
			"event", "user_activation_failed",
			"token", req.Token,
			"error", err,
		)
		// Return internal server error
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update activation token status",
			Err:     err,
		}
	}

	// Update the user status to active
	err = u.updateStatus(ctx, userData.Id, constant.USER_STATUS_ACTIVE)
	if err != nil {
		// Log error if unable to activate user account
		u.logger.Errorw(ctx, "failed to activate user account",
			"event", "user_activation_failed",
			"userId", userData.Id,
			"error", err,
		)
		// Return internal server error
		return domain.UserActivationClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to activate user account",
			Err:     err,
		}
	}

	// Log success and return successful response
	u.logger.Infow(ctx, "user account activated successfully",
		"event", "user_activation_success",
		"userId", userData.Id,
	)

	return domain.UserActivationClientResponse{
		Message: "Account has been activated successfully",
	}, nil
}

// ResendActivation resends the activation email to the user.
func (u *userusecase) ResendActivation(ctx context.Context, req domain.UserResendActivationClientRequest) (domain.UserResendActivationClientResponse, domain.ResponseError) {
	// Fetch user data by username
	userData, err := u.getUserByUsername(ctx, req.Username)
	if err != nil || userData.Id == 0 {
		// Log error if the username is invalid
		u.logger.Errorw(ctx, "invalid username",
			"event", "user_resend_activation_failed",
			"username", req.Username,
			"error", err,
		)
		// Return bad request error if the username is incorrect
		return domain.UserResendActivationClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Username is incorrect",
			Err:     err,
		}
	}

	// Check if the user's account is in a valid state for activation
	if userData.Status != constant.USER_STATUS_PENDING {
		var message string
		// Determine message based on user status
		switch userData.Status {
		case constant.USER_STATUS_ACTIVE:
			message = "Account already active"
		case constant.USER_STATUS_INACTIVE:
			message = "Account is inactive"
		default:
			message = "Account is banned"
		}
		// Log and return response with the appropriate message based on status
		u.logger.Warnw(ctx, message,
			"event", "user_resend_activation_failed",
			"userId", userData.Id,
		)
		return domain.UserResendActivationClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: message,
			Err:     nil,
		}
	}

	// Create a new activation token for the user
	tokenId, token, err := u.createActivationToken(ctx, userData.Id)
	if err != nil || tokenId == 0 || token == "" {
		// Log error if unable to create the activation token
		u.logger.Errorw(ctx, "failed to create activation token",
			"event", "user_resend_activation_failed",
			"userId", userData.Id,
			"error", err,
		)
		// Return internal server error if token creation fails
		return domain.UserResendActivationClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to create activation token",
			Err:     err,
		}
	}

	// Generate the activation link with the token
	link := u.getActivationLink()
	link = u.activationLinkMacroReplacement(link, tokenId, token)

	// Load the email template for sending the activation link
	templatePath := u.conf.GetActivationEmailTemplate()
	template, err := utils.FindFileContent(templatePath)
	if err != nil {
		// Log error if unable to load the email template
		u.logger.Errorw(ctx, "failed to load email template",
			"event", "user_resend_activation_failed",
			"userId", userData.Id,
			"error", err,
		)
		// Return internal server error if template loading fails
		return domain.UserResendActivationClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to load email template",
			Err:     err,
		}
	}

	// Replace macros in the template with actual values
	emailTemplate := u.activationTemplateMacroReplacement(template, userData.Name, link)

	// Send the activation email if template is successfully prepared
	if emailTemplate != "" {
		err = u.sendActivation(ctx, userData.Username, template)
		if err != nil {
			// Log error if unable to send the activation email
			u.logger.Errorw(ctx, "failed to send activation email",
				"event", "user_resend_activation_failed",
				"userId", userData.Id,
				"error", err,
			)
			// Return internal server error if email sending fails
			return domain.UserResendActivationClientResponse{}, errorRes{
				Code:    http.StatusInternalServerError,
				Message: "Failed to send activation email",
				Err:     err,
			}
		}

		// Log success and return success response
		u.logger.Infow(ctx, "activation email resent successfully",
			"event", "user_resend_activation_success",
			"userId", userData.Id,
		)
	}

	return domain.UserResendActivationClientResponse{
		Message: "Please check your email to activate your account",
	}, nil
}

// ForgotPassword handles the request for a user to reset their password.
// It checks the username, validates the account status, generates a reset token,
// sends a password reset email, and returns the appropriate response.
func (u *userusecase) ForgotPassword(ctx context.Context, req domain.UserForgotPasswordClientRequest) (domain.UserForgotPasswordClientResponse, domain.ResponseError) {
	// Fetch user by username
	userData, err := u.getUserByUsername(ctx, req.Username)
	if err != nil {
		// Log error if user retrieval fails
		u.logger.Errorw(ctx, "failed to fetch user by username",
			"event", "user_forgot_password_failed",
			"username", req.Username,
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to fetch user data",
			Err:     err,
		}
	}

	// Validate user existence
	if userData.Id == 0 {
		// Log and return response if username is incorrect
		u.logger.Warnw(ctx, "incorrect username",
			"event", "user_forgot_password_failed",
			"username", req.Username,
		)
		return domain.UserForgotPasswordClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Username is incorrect",
			Err:     nil,
		}
	}

	// Check user account status
	if userData.Status != constant.USER_STATUS_ACTIVE {
		var message string
		// Determine appropriate message based on account status
		switch userData.Status {
		case constant.USER_STATUS_INACTIVE:
			message = "Account is inactive"
		case constant.USER_STATUS_PENDING:
			message = "Account is pending"
		default:
			message = "Account is banned"
		}
		// Log and return response with the message
		u.logger.Warnw(ctx, message,
			"event", "user_forgot_password_failed",
			"userId", userData.Id,
		)
		return domain.UserForgotPasswordClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: message,
			Err:     nil,
		}
	}

	// Generate password reset token
	tokenId, token, err := u.createPasswordResetToken(ctx, userData.Id)
	if err != nil || tokenId == 0 || token == "" {
		// Log error if token creation fails
		u.logger.Errorw(ctx, "unable to create reset token",
			"event", "user_forgot_password_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to create reset token",
			Err:     err,
		}
	}

	// Generate reset link with token
	link := u.getPasswordResetLink()
	link = u.passwordResetLinkMacroReplacement(link, token)

	// Load email template for password reset
	templatePath := u.conf.GetPasswordResetTemplate()
	template, err := utils.FindFileContent(templatePath)
	if err != nil {
		// Log error if unable to load email template
		u.logger.Errorw(ctx, "unable to load email template",
			"event", "user_forgot_password_failed",
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to load email template",
			Err:     err,
		}
	}

	// Replace placeholders in the email template
	template = u.passwordResetTemplateMacroReplacement(template, userData.Name, link)

	// Send password reset email with the generated template
	err = u.sendPasswordReset(ctx, userData.Username, template)
	if err != nil {
		// Log error if sending reset email fails
		u.logger.Errorw(ctx, "failed to send password reset email",
			"event", "user_forgot_password_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to send reset email",
			Err:     err,
		}
	}

	// Log success and return response indicating reset link has been sent
	u.logger.Infow(ctx, "password reset link sent successfully",
		"event", "user_forgot_password_success",
		"userId", userData.Id,
	)

	return domain.UserForgotPasswordClientResponse{
		Message: "Reset link sent to your email",
	}, nil
}

// ResetPassword handles the password reset process after the user clicks the reset link.
// It validates the reset token, checks user account status, hashes the new password,
// updates the user's password, and returns the appropriate response.
func (u *userusecase) ResetPassword(ctx context.Context, req domain.UserResetPasswordClientRequest) (domain.UserResetPasswordClientResponse, domain.ResponseError) {
	// Fetch password reset token data
	tokenData, err := u.getPasswordResetByToken(ctx, req.Token)
	if err != nil || tokenData.Id == 0 {
		// Log error if token is invalid or expired
		u.logger.Errorw(ctx, "invalid or expired reset token",
			"event", "user_reset_password_failed",
			"token", req.Token,
			"error", err,
		)
		return domain.UserResetPasswordClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Invalid reset link",
			Err:     err,
		}
	}

	// Ensure the token is active and not expired
	if tokenData.Status != constant.USER_PASSWORD_RESET_STATUS_ACTIVE {
		// Return error if token has already been used
		return domain.UserResetPasswordClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Link already used",
			Err:     nil,
		}
	}
	if tokenData.ExpiresAt.Before(time.Now()) {
		// Return error if the reset token has expired
		return domain.UserResetPasswordClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Link expired",
			Err:     nil,
		}
	}

	// Fetch user data associated with the reset token
	userData, err := u.getUserByUserID(ctx, tokenData.UserId)
	if err != nil || userData.Status != constant.USER_STATUS_ACTIVE {
		// Log and return error if the account is inactive or invalid
		u.logger.Warnw(ctx, "account status invalid",
			"event", "user_reset_password_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserResetPasswordClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Account is not active",
			Err:     nil,
		}
	}

	// Hash the new password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password+userData.Salt), u.conf.GetPasswordHashCost())
	if err != nil {
		// Return error if password hashing fails
		return domain.UserResetPasswordClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to hash password",
			Err:     err,
		}
	}

	// Update the user's password in the database
	err = u.UpdatePassword(ctx, userData.Id, hashPassword)
	if err != nil {
		// Return error if password update fails
		return domain.UserResetPasswordClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update password",
			Err:     err,
		}
	}

	// Mark the reset token as inactive after successful password change
	err = u.updatePasswordResetStatus(ctx, tokenData.Id, constant.USER_PASSWORD_RESET_STATUS_INACTIVE)
	if err != nil {
		// Return error if unable to update token status
		return domain.UserResetPasswordClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update token status",
			Err:     err,
		}
	}

	// Return success response indicating password has been reset successfully
	return domain.UserResetPasswordClientResponse{
		Message: "Password has been reset successfully",
	}, nil
}

// RefreshToken validates the refresh token, ensuring it's not expired, not revoked, and that the associated user account is active.
func (u *userusecase) RefreshToken(ctx context.Context, req domain.UserRefreshTokenClientRequest) (domain.UserRefreshTokenClientResponse, domain.ResponseError) {

	// Fetch the refresh token data from the database
	refreshData, err := u.getRefreshTokenData(ctx, req.RefreshToken)
	if err != nil || refreshData.Id == 0 || refreshData.Revoked {
		u.logger.Warnw(ctx, "revoked or incorrect refresh token",
			"event", "user_refresh_token_validation_failed",
			"token", req.RefreshToken,
		)
		return domain.UserRefreshTokenClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is revoked or incorrect",
			Err:     nil,
		}
	}

	// Validate the token's expiration
	if refreshData.ExpiresAt.Before(time.Now()) {
		u.logger.Warnw(ctx, "incorrect or expired token",
			"event", "user_refresh_token_validation_failed",
			"token", req.RefreshToken,
		)
		return domain.UserRefreshTokenClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Token is incorrect or expired",
			Err:     nil,
		}
	}

	// Fetch the user data
	userData, err := u.getUserByUserID(ctx, refreshData.UserId)

	if err != nil {
		u.logger.Errorw(ctx, "failed on get user information by user ids",
			"event", "user_refresh_token_validation_failed",
			"userId", refreshData.UserId,
			"error", err,
		)

		return domain.UserRefreshTokenClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
			Err:     err,
		}
	}

	if userData.Status != constant.USER_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "invalid user status",
			"event", "user_refresh_token_validation_failed",
			"userId", refreshData.UserId,
		)

		return domain.UserRefreshTokenClientResponse{}, errorRes{
			Code:    http.StatusBadRequest,
			Message: "Account is not active",
			Err:     nil,
		}
	}

	// Create a new access token for the user
	accessToken, err := u.token.CreateAccessToken(userData.Id, userData.Username, userData.Name, u.getAccessTokenExpiry())
	if err != nil {
		return domain.UserRefreshTokenClientResponse{}, errorRes{
			Code:    http.StatusInternalServerError,
			Message: "Unable to create access token",
			Err:     err,
		}
	}

	// Handle refresh token rotation if enabled
	var refreshTokenType, finalRefreshToken string
	if u.refreshTokenRotationEnabled() {
		refreshTokenType = constant.REFRESH_TOKEN_TYPE_ROTATING
		err := u.RevokeRefreshToken(ctx, userData.Id, req.RefreshToken)
		if err != nil {
			return domain.UserRefreshTokenClientResponse{}, errorRes{
				Code:    http.StatusInternalServerError,
				Message: "Failed to revoke old token",
				Err:     err,
			}
		}

		// Create a new refresh token and store it
		finalRefreshToken, err = u.token.CreateRefreshToken(userData.Id, u.getRefreshTokenExpiry())
		if err != nil {
			return domain.UserRefreshTokenClientResponse{}, errorRes{
				Code:    http.StatusInternalServerError,
				Message: "Failed to create refresh token",
				Err:     err,
			}
		}

		// Store the new refresh token in the database
		_, err = u.createRefreshToken(ctx, userData.Id, finalRefreshToken, u.getRefreshTokenExpiry())
		if err != nil {
			return domain.UserRefreshTokenClientResponse{}, errorRes{
				Code:    http.StatusInternalServerError,
				Message: "Failed to store refresh token",
				Err:     err,
			}
		}
	} else {
		// If rotation is not enabled, retain the original refresh token
		refreshTokenType = constant.REFRESH_TOKEN_TYPE_STATIC
		finalRefreshToken = req.RefreshToken
	}

	// Return the response with the new access and refresh tokens
	return domain.UserRefreshTokenClientResponse{
		AccessToken:      accessToken,
		RefreshTokenType: refreshTokenType,
		RefreshToken:     finalRefreshToken,
	}, nil
}

// createActivationToken generates a new activation token for the user and ensures its uniqueness by checking the database.
func (u *userusecase) createActivationToken(ctx context.Context, userid int) (int, string, error) {
	// Generate a random activation token
	activationToken := utils.GenerateRandomString(25)

	// Check if the token already exists in the database
	tokenData, err := u.getActivationByToken(ctx, activationToken)
	if err != nil {
		return 0, "", err
	}

	// If token already exists, recursively create a new one
	if tokenData.Id != 0 {
		return u.createActivationToken(ctx, userid)
	}

	// Prepare the token data for storage
	tokenData = domain.UserActivationToken{
		UserId:    userid,
		Token:     activationToken,
		Status:    constant.USER_ACTIVATION_TOKEN_STATUS_ACTIVE,
		ExpiresAt: u.getActivationLinkExpiry(),
	}

	// Store the token in the database
	tokenId, err := u.createActivation(ctx, tokenData)
	if err != nil {
		return 0, "", err
	}
	return tokenId, activationToken, nil
}

// createRefreshToken generates a new refresh token for the user and stores it in the database.
func (u *userusecase) createRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) (int, error) {
	// Prepare the refresh token data
	refreshTokenData := domain.UserRefreshToken{
		UserId:    userid,
		Token:     token,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	// Store the refresh token in the database
	refreshTokenId, err := u.storeRefreshToken(ctx, refreshTokenData)
	if err != nil {
		return 0, err
	}
	return refreshTokenId, nil
}

// createPasswordResetToken generates a new password reset token for the user, ensuring its uniqueness.
func (u *userusecase) createPasswordResetToken(ctx context.Context, userid int) (int, string, error) {
	// Check if there's an active password reset for the user
	passwordResetData, err := u.getActivePasswordResetByUserID(ctx, userid)
	if err != nil {
		return 0, "", err
	}

	// If an active reset token exists, return it
	if passwordResetData.Id != 0 && passwordResetData.Token != "" {
		return passwordResetData.Id, passwordResetData.Token, nil
	}

	// Generate a new password reset token
	passwordResetToken := utils.GenerateRandomString(25)

	// Ensure the token is unique by checking the database
	alreadyExiststData, err := u.getPasswordResetByToken(ctx, passwordResetToken)
	if err != nil {
		return 0, "", err
	}

	// If the token already exists, recursively generate a new one
	if alreadyExiststData.Id != 0 {
		return u.createPasswordResetToken(ctx, userid)
	}

	// Prepare the password reset data for storage
	passwordResetData = domain.UserPasswordReset{
		UserId:    userid,
		Token:     passwordResetToken,
		Status:    constant.USER_PASSWORD_RESET_STATUS_ACTIVE,
		ExpiresAt: u.getPasswordResetLinkExpiry(),
	}

	// Store the password reset token in the database
	passwordResetId, err := u.mysql.CreatePasswordReset(ctx, passwordResetData)
	if err != nil {
		return 0, "", err
	}
	return passwordResetId, passwordResetToken, nil
}

// checkLoginFailedAttemptLimitReached checks if the user has reached the maximum number of failed login attempts.
func (u *userusecase) checkLoginFailedAttemptLimitReached(ctx context.Context, userId int) (int, error) {
	// Get the number of failed login attempts within the defined session period
	attempCount, err := u.getUserLoginFailedAttemptCount(ctx, userId, u.getLoginAttemptSessionPeriod())
	if err != nil {
		return constant.LOGIN_ATTEMPT_FAILED, err
	}

	// If the maximum number of failed attempts is reached, return the corresponding code
	if attempCount >= u.getMaxLoginAttempt() {
		return constant.LOGIN_ATTEMPT_MAX_REACHED, nil
	}

	// Otherwise, return success
	return constant.LOGIN_ATTEMPT_SUCCESS, nil
}

// comparePassword compares a provided password with the stored password hash and salt.
func (u *userusecase) comparePassword(ctx context.Context, password string, passwordHash string, saltHash string) (bool, error) {
	// Use bcrypt to compare the password with the hashed value
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password+saltHash))
	if err != nil {
		return false, err
	}
	return true, nil
}

// newSaltHash generates a new salt for password hashing.
func (u *userusecase) newSaltHash() (string, error) {
	// Generate a random salt string
	saltRaw := utils.GenerateRandomString(10)

	// Hash the salt using bcrypt
	salt, err := bcrypt.GenerateFromPassword([]byte(saltRaw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(salt), nil
}

// passwordResetLinkMacroReplacement replaces macros in the password reset link with the provided token.
func (u *userusecase) passwordResetLinkMacroReplacement(passwordResetLink string, token string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_TOKEN_MACRO, token)

	return s.Replace(passwordResetLink)
}

// passwordResetTemplateMacroReplacement replaces macros in the email template with actual values.
func (u *userusecase) passwordResetTemplateMacroReplacement(template string, name string, passwordResetLink string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_APP_NAME_MACRO, u.appName,
		USER_PASSWORD_RESET_NAME_MACRO, name,
		USER_PASSWORD_RESET_LINK_MACRO, passwordResetLink)

	return s.Replace(template)
}

// sendPasswordReset simulates sending the password reset email to the user (no actual implementation here).
func (u *userusecase) sendPasswordReset(ctx context.Context, email string, template string) error {
	return nil
}

// activationLinkMacroReplacement replaces macros in the activation link with the provided token data.
func (u *userusecase) activationLinkMacroReplacement(activationLink string, tokenId int, token string) string {
	s := strings.NewReplacer(
		USER_ACTIVATION_TOKEN_ID_MACRO, strconv.Itoa(tokenId),
		USER_ACTIVATION_TOKEN_MACRO, token)

	return s.Replace(activationLink)
}

// activationTemplateMacroReplacement replaces macros in the activation email template with actual values.
func (u *userusecase) activationTemplateMacroReplacement(template string, name string, activationLink string) string {
	s := strings.NewReplacer(
		USER_ACTIVATION_APP_NAME_MACRO, u.appName,
		USER_ACTIVATION_NAME_MACRO, name,
		USER_ACTIVATION_LINK_MACRO, activationLink)

	return s.Replace(template)

}

func (u *userusecase) sendActivation(ctx context.Context, email string, template string) error {

	// Here, send the email using a third-party service, SMTP, or another method
	err := u.sendEmail(email, template)
	if err != nil {
		// Log error details and return the error
		u.logger.Errorw(ctx, "failed to send activation email",
			"event", "send_activation_email_failed",
			"email", email,
			"error", err,
		)
		return err
	}

	// Log success message
	u.logger.Infow(ctx, "activation email sent successfully",
		"event", "send_activation_email_success",
		"email", email,
	)

	return nil
}

// sendEmail simulates sending an email
func (u *userusecase) sendEmail(email string, content string) error {
	// For example, using an SMTP server or third-party API like SendGrid, etc.
	// This can be replaced with actual email-sending logic
	return nil
}
