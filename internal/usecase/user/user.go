package user

import (
	"context"
	"mayilon/config"
	"mayilon/internal/constant"
	"mayilon/internal/domain"
	"mayilon/internal/port"
	"mayilon/internal/utils"
	"net/http"

	"time"

	"golang.org/x/crypto/bcrypt"
)

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

type userusecase struct {
	appName     string
	logger      port.Logger
	mysql       port.RepositoryMySQL
	conf        config.User
	tokenEngine port.Token
}

func New(loggerIns port.Logger, mysqlIns port.RepositoryMySQL, appName string, userConfIns config.User) domain.UserSvr {
	return &userusecase{
		mysql:  mysqlIns,
		logger: loggerIns,
		conf:   userConfIns,
	}
}

type HTTPError struct {
	Code    int
	Message string
	Err     error
}

func (e HTTPError) Error() string {
	return e.Message
}

func (e HTTPError) StatusCode() int {
	return e.Code
}

func (e HTTPError) MessageText() string {
	return e.Message
}

func (e HTTPError) Unwrap() error {
	return e.Err
}

func (u *userusecase) Login(ctx context.Context, username, password string) (domain.UserLoginClientResponse, domain.HTTPError) {
	userData, err := u.getUserByUsername(ctx, username)
	if err != nil || userData.Id == 0 {
		u.logger.Warnw(ctx, "failed to find user by username",
			"event", "user_login_failed",
			"username", username,
			"error", err,
		)
		return domain.UserLoginClientResponse{}, HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Username or password is incorrect",
			Err:     nil,
		}
	}

	attemptStatus, err := u.checkLoginFailedAttempt(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "error checking failed login attempts",
			"event", "login_attempt_check_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserLoginClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Could not validate login attempt",
			Err:     err,
		}
	}

	if attemptStatus == constant.LOGIN_ATTEMPT_MAX_REACHED {
		u.logger.Warnw(ctx, "max login attempts reached",
			"event", "login_blocked",
			"userId", userData.Id,
		)
		return domain.UserLoginClientResponse{}, HTTPError{
			Code:    http.StatusTooManyRequests,
			Message: "Maximum login attempts reached. Please try again later.",
			Err:     nil,
		}
	}

	passwordMatch, err := u.checkPassword(ctx, password, userData.Password, userData.Salt)
	if err != nil || !passwordMatch {
		_, _ = u.createLoginAttempt(ctx, userData.Id, false)
		u.logger.Warnw(ctx, "password did not match",
			"event", "password_mismatch",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserLoginClientResponse{}, HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Username or password is incorrect",
			Err:     nil,
		}
	}
	_, _ = u.createLoginAttempt(ctx, userData.Id, true)

	userData, err = u.getUserByUserid(ctx, userData.Id)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user data after login",
			"event", "fetch_user_by_id_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserLoginClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Could not retrieve user information",
			Err:     err,
		}
	}

	if userData.Status != constant.USER_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "inactive user tried to login",
			"event", "inactive_user_login",
			"userId", userData.Id,
		)
		return domain.UserLoginClientResponse{}, HTTPError{
			Code:    http.StatusForbidden,
			Message: "Your account is not active. Please contact support.",
			Err:     nil,
		}
	}

	accessToken, err := u.tokenEngine.CreateAccessToken(userData.Id, userData.Username, userData.Name, u.getAccessTokenExpiry())
	if err != nil {
		u.logger.Errorw(ctx, "failed to create access token",
			"event", "access_token_generation_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserLoginClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Could not generate access token",
			Err:     err,
		}
	}

	var refreshToken, refreshTokenType string
	if u.refreshTokenEnabled() {
		if u.refreshTokenRotationEnabled() {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_ROTATING
		} else {
			refreshTokenType = constant.REFRESH_TOKEN_TYPE_STATIC
		}

		refreshToken, err = u.tokenEngine.CreateRefreshToken(userData.Id, u.getRefreshTokenExpiry())
		if err != nil {
			u.logger.Errorw(ctx, "failed to create refresh token",
				"event", "refresh_token_generation_failed",
				"userId", userData.Id,
				"error", err,
			)
			return domain.UserLoginClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Could not generate refresh token",
				Err:     err,
			}
		}

		expiresAt, err := u.tokenEngine.GetRefreshTokenExpiry(refreshToken)
		if err != nil {
			u.logger.Errorw(ctx, "failed to get refresh token expiry",
				"event", "refresh_token_expiry_parse_failed",
				"userId", userData.Id,
				"error", err,
			)
			return domain.UserLoginClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Could not determine refresh token expiry",
				Err:     err,
			}
		}

		_, err = u.storeRefreshToken(ctx, userData.Id, refreshToken, expiresAt)

		if err != nil {
			return domain.UserLoginClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Failed to store refresh token",
				Err:     err,
			}
		}
	}

	u.logger.Infow(ctx, "user login successful",
		"event", "user_login_success",
		"userId", userData.Id,
	)

	return domain.UserLoginClientResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshTokenType: refreshTokenType,
	}, nil
}

func (u *userusecase) Logout(ctx context.Context, refreshToken string) (domain.UserLogoutClientResponse, domain.HTTPError) {
	// Attempt to get user data from refresh token
	userid, expiresAt, err := u.tokenEngine.GetRefreshTokenData(refreshToken)
	if err != nil {
		u.logger.Errorw(ctx, "unable to parse refresh token",
			"event", "logout_failed",
			"refreshToken", refreshToken,
			"error", err,
		)
		return domain.UserLogoutClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Unable to parse token",
			Err:     err,
		}
	}

	if userid == 0 {
		u.logger.Warnw(ctx, "incorrect user ID from refresh token",
			"event", "logout_failed",
			"refreshToken", refreshToken,
		)
		return domain.UserLogoutClientResponse{}, HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Incorrect token",
			Err:     nil,
		}
	}

	if expiresAt.Before(time.Now()) {
		u.logger.Warnw(ctx, "token expired",
			"event", "logout_failed",
			"refreshToken", refreshToken,
			"expiresAt", expiresAt,
		)
		return domain.UserLogoutClientResponse{}, HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Token expired",
			Err:     nil,
		}
	}

	// Attempt to revoke the refresh token
	err = u.revokedRefreshToken(ctx, userid, refreshToken)
	if err != nil {
		u.logger.Errorw(ctx, "unable to revoke refresh token",
			"event", "logout_failed",
			"userId", userid,
			"refreshToken", refreshToken,
			"error", err,
		)
		return domain.UserLogoutClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to revoke token",
			Err:     err,
		}
	}

	// Log successful logout
	u.logger.Infow(ctx, "user logged out successfully",
		"event", "logout_success",
		"userId", userid,
		"refreshToken", refreshToken,
	)

	return domain.UserLogoutClientResponse{
		Message: "Logout successful",
	}, HTTPError{}
}
func (u *userusecase) Register(ctx context.Context, username, password, name string) (domain.UserRegisterClientResponse, domain.HTTPError) {
	// Check if username already exists
	existingUser, err := u.getUserByUsername(ctx, username)
	if err != nil {
		u.logger.Errorw(ctx, "failed to check if username exists",
			"event", "register_failed",
			"username", username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to check if username exists",
			Err:     err,
		}
	}
	if existingUser.Id != 0 {
		u.logger.Warnw(ctx, "username already exists",
			"event", "register_failed",
			"username", username,
		)
		return domain.UserRegisterClientResponse{}, HTTPError{
			Code:    http.StatusConflict,
			Message: "Username already exists",
			Err:     nil,
		}
	}

	// Create new user
	saltHash, err := u.newSaltHash()
	if err != nil {
		u.logger.Errorw(ctx, "failed to generate salt hash",
			"event", "register_failed",
			"username", username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate salt hash",
			Err:     err,
		}
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		u.logger.Errorw(ctx, "failed to hash password",
			"event", "register_failed",
			"username", username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to hash password",
			Err:     err,
		}
	}

	// Prepare user data for creation
	var userData = domain.User{
		Username: username,
		Password: string(hashPassword),
		Salt:     saltHash,
		Name:     name,
		State:    constant.USER_STATE_INITIAL,
		Status:   constant.USER_STATUS_PENDING,
	}

	userID, err := u.createUser(ctx, userData)
	if err != nil {
		u.logger.Errorw(ctx, "failed to create new user",
			"event", "register_failed",
			"username", username,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create new user",
			Err:     err,
		}
	}

	userData, err = u.getUserByUserid(ctx, userID)
	if err != nil || userData.Id == 0 {
		u.logger.Errorw(ctx, "failed to fetch newly created user",
			"event", "register_failed",
			"userId", userID,
			"error", err,
		)
		return domain.UserRegisterClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch newly created user",
			Err:     err,
		}
	}

	// Send activation link if user status is pending
	if userData.Status == constant.USER_STATUS_PENDING {
		tokenID, activationToken, err := u.createActivationToken(ctx, userData.Id)
		if err != nil {
			u.logger.Errorw(ctx, "failed to create activation token",
				"event", "register_failed",
				"userId", userData.Id,
				"error", err,
			)
			return domain.UserRegisterClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Failed to create activation token",
				Err:     err,
			}
		}

		if tokenID != 0 && activationToken != "" {
			link := u.getActivationLink()
			link = u.activationLinkMacroReplacement(link, tokenID, activationToken)

			if link != "" {
				templatePath := u.conf.GetActivationEmailTemplate()

				template, err := utils.FindFileContent(templatePath)
				if err != nil {
					u.logger.Errorw(ctx, "failed to load email template",
						"event", "register_failed",
						"userId", userData.Id,
						"error", err,
					)
					return domain.UserRegisterClientResponse{}, HTTPError{
						Code:    http.StatusInternalServerError,
						Message: "Failed to load email template",
						Err:     err,
					}
				}

				emailTemplate := u.activationTemplateMacroReplacement(template, userData.Name, link)

				if emailTemplate != "" {
					err = u.sendActivation(ctx, userData.Username, emailTemplate)
					if err != nil {
						u.logger.Errorw(ctx, "failed to send activation email",
							"event", "register_failed",
							"userId", userData.Id,
							"error", err,
						)
						return domain.UserRegisterClientResponse{}, HTTPError{
							Code:    http.StatusInternalServerError,
							Message: "Failed to send activation email",
							Err:     err,
						}
					}

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

	u.logger.Infow(ctx, "user registered successfully",
		"event", "register_success",
		"userId", userData.Id,
	)

	return domain.UserRegisterClientResponse{
		Message: "Account created successfully.",
	}, nil
}

func (u *userusecase) ActivateUser(ctx context.Context, token string) (domain.UserActivationClientResponse, domain.HTTPError) {
	// Fetch user activation data by token
	tokenData, err := u.getUserActivationByToken(ctx, token)
	if err != nil || tokenData.Id == 0 {
		u.logger.Errorw(ctx, "invalid or expired token",
			"event", "user_activation_failed",
			"token", token,
			"error", err,
		)
		return domain.UserActivationClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid or expired token",
			Err:     err,
		}
	}

	// Check if the activation token is still active
	if tokenData.Status != constant.USER_ACTIVATION_TOKEN_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "activation token already used",
			"event", "user_activation_failed",
			"token", token,
		)
		return domain.UserActivationClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Activation link already used",
			Err:     nil,
		}
	}

	// Check if the activation token has expired
	if tokenData.ExpiresAt.Before(time.Now()) {
		u.logger.Warnw(ctx, "activation link expired",
			"event", "user_activation_failed",
			"token", token,
		)
		return domain.UserActivationClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Activation link expired",
			Err:     nil,
		}
	}

	// Fetch user data by user ID
	userData, err := u.getUserByUserid(ctx, tokenData.UserId)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user data for activation",
			"event", "user_activation_failed",
			"token", token,
			"userId", tokenData.UserId,
			"error", err,
		)
		return domain.UserActivationClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch user data",
			Err:     err,
		}
	}

	// Handle different user statuses
	if userData.Status != constant.USER_STATUS_PENDING {
		var message string
		switch userData.Status {
		case constant.USER_STATUS_ACTIVE:
			message = "Account already active"
		case constant.USER_STATUS_INACTIVE:
			message = "Account is inactive"
		default:
			message = "Account is banned"
		}
		u.logger.Warnw(ctx, message,
			"event", "user_activation_failed",
			"userId", userData.Id,
		)
		return domain.UserActivationClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: message,
			Err:     nil,
		}
	}

	// Update activation token status to inactive
	err = u.updatedActivationtatus(ctx, tokenData.Id, constant.USER_ACTIVATION_TOKEN_STATUS_INACTIVE)
	if err != nil {
		u.logger.Errorw(ctx, "failed to update activation token status",
			"event", "user_activation_failed",
			"token", token,
			"error", err,
		)
		return domain.UserActivationClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update activation token status",
			Err:     err,
		}
	}

	// Update user status to active
	err = u.updateStatus(ctx, userData.Id, constant.USER_STATUS_ACTIVE)
	if err != nil {
		u.logger.Errorw(ctx, "failed to activate user account",
			"event", "user_activation_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserActivationClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to activate user account",
			Err:     err,
		}
	}

	// Successful activation
	u.logger.Infow(ctx, "user account activated successfully",
		"event", "user_activation_success",
		"userId", userData.Id,
	)

	return domain.UserActivationClientResponse{
		Message: "Account has been activated successfully",
	}, nil
}

func (u *userusecase) ResendActivation(ctx context.Context, username string) (domain.UserResendActivationClientResponse, domain.HTTPError) {
	// Fetch user by username
	userData, err := u.getUserByUsername(ctx, username)
	if err != nil || userData.Id == 0 {
		u.logger.Errorw(ctx, "invalid username",
			"event", "user_resend_activation_failed",
			"username", username,
			"error", err,
		)
		return domain.UserResendActivationClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Username is incorrect",
			Err:     err,
		}
	}

	// Check if the user's account is in a valid state for activation
	if userData.Status != constant.USER_STATUS_PENDING {
		var message string
		switch userData.Status {
		case constant.USER_STATUS_ACTIVE:
			message = "Account already active"
		case constant.USER_STATUS_INACTIVE:
			message = "Account is inactive"
		default:
			message = "Account is banned"
		}
		u.logger.Warnw(ctx, message,
			"event", "user_resend_activation_failed",
			"userId", userData.Id,
		)
		return domain.UserResendActivationClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: message,
			Err:     nil,
		}
	}

	// Create new activation token
	tokenId, token, err := u.createActivationToken(ctx, userData.Id)
	if err != nil || tokenId == 0 || token == "" {
		u.logger.Errorw(ctx, "failed to create activation token",
			"event", "user_resend_activation_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserResendActivationClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to create activation token",
			Err:     err,
		}
	}

	// Generate the activation link
	link := u.getActivationLink()
	link = u.activationLinkMacroReplacement(link, tokenId, token)

	// Load email template
	templatePath := u.conf.GetActivationEmailTemplate()

	template, err := utils.FindFileContent(templatePath)
	if err != nil {
		u.logger.Errorw(ctx, "failed to load email template",
			"event", "user_resend_activation_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserResendActivationClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to load email template",
			Err:     err,
		}
	}

	emailTemplate := u.activationTemplateMacroReplacement(template, userData.Name, link)

	if emailTemplate != "" {
		// Send the activation email
		err = u.sendActivation(ctx, userData.Username, template)
		if err != nil {
			u.logger.Errorw(ctx, "failed to send activation email",
				"event", "user_resend_activation_failed",
				"userId", userData.Id,
				"error", err,
			)
			return domain.UserResendActivationClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Failed to send activation email",
				Err:     err,
			}
		}

		// Successful resend
		u.logger.Infow(ctx, "activation email resent successfully",
			"event", "user_resend_activation_success",
			"userId", userData.Id,
		)
	}

	return domain.UserResendActivationClientResponse{
		Message: "Please check your email to activate your account",
	}, nil
}

func (u *userusecase) ForgotPassword(ctx context.Context, username string) (domain.UserForgotPasswordClientResponse, domain.HTTPError) {
	// Fetch user by username
	userData, err := u.getUserByUsername(ctx, username)
	if err != nil {
		u.logger.Errorw(ctx, "failed to fetch user by username",
			"event", "user_forgot_password_failed",
			"username", username,
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to fetch user data",
			Err:     err,
		}
	}

	// Validate user existence
	if userData.Id == 0 {
		u.logger.Warnw(ctx, "incorrect username",
			"event", "user_forgot_password_failed",
			"username", username,
		)
		return domain.UserForgotPasswordClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Username is incorrect",
			Err:     nil,
		}
	}

	// Check user account status
	if userData.Status != constant.USER_STATUS_ACTIVE {
		var message string
		switch userData.Status {
		case constant.USER_STATUS_INACTIVE:
			message = "Account is inactive"
		case constant.USER_STATUS_PENDING:
			message = "Account is pending"
		default:
			message = "Account is banned"
		}
		u.logger.Warnw(ctx, message,
			"event", "user_forgot_password_failed",
			"userId", userData.Id,
		)
		return domain.UserForgotPasswordClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: message,
			Err:     nil,
		}
	}

	// Generate reset token
	tokenId, token, err := u.createPasswordResetToken(ctx, userData.Id)
	if err != nil || tokenId == 0 || token == "" {
		u.logger.Errorw(ctx, "unable to create reset token",
			"event", "user_forgot_password_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to create reset token",
			Err:     err,
		}
	}

	// Generate reset link
	link := u.getPasswordResetLink()
	link = u.passwordResetLinkMacroReplacement(link, token)

	// Load email template
	templatePath := u.conf.GetPasswordResetTemplate()
	template, err := utils.FindFileContent(templatePath)
	if err != nil {
		u.logger.Errorw(ctx, "unable to load email template",
			"event", "user_forgot_password_failed",
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to load email template",
			Err:     err,
		}
	}

	// Replace template macros
	template = u.passwordResetTemplateMacroReplacement(template, userData.Name, link)

	// Send reset email
	err = u.sendPasswordReset(ctx, userData.Username, template)
	if err != nil {
		u.logger.Errorw(ctx, "failed to send password reset email",
			"event", "user_forgot_password_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserForgotPasswordClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to send reset email",
			Err:     err,
		}
	}

	u.logger.Infow(ctx, "password reset link sent successfully",
		"event", "user_forgot_password_success",
		"userId", userData.Id,
	)

	return domain.UserForgotPasswordClientResponse{
		Message: "Reset link sent to your email",
	}, nil
}

func (u *userusecase) ResetPassword(ctx context.Context, token, newPassword string) (domain.UserResetPasswordClientResponse, domain.HTTPError) {
	// Fetch password reset token data
	tokenData, err := u.getPasswordResetByToken(ctx, token)
	if err != nil || tokenData.Id == 0 {
		u.logger.Errorw(ctx, "invalid or expired reset token",
			"event", "user_reset_password_failed",
			"token", token,
			"error", err,
		)
		return domain.UserResetPasswordClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid reset link",
			Err:     err,
		}
	}

	// Check if token is active and not expired
	if tokenData.Status != constant.USER_PASSWORD_RESET_STATUS_ACTIVE {
		return domain.UserResetPasswordClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Link already used",
			Err:     nil,
		}
	}
	if tokenData.ExpiresAt.Before(time.Now()) {
		return domain.UserResetPasswordClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Link expired",
			Err:     nil,
		}
	}

	// Fetch user data
	userData, err := u.getUserByUserid(ctx, tokenData.UserId)
	if err != nil || userData.Status != constant.USER_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "account status invalid",
			"event", "user_reset_password_failed",
			"userId", userData.Id,
			"error", err,
		)
		return domain.UserResetPasswordClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Account is not active",
			Err:     nil,
		}
	}

	// Hash new password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword+userData.Salt), u.conf.GetPasswordHashCost())
	if err != nil {
		return domain.UserResetPasswordClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to hash password",
			Err:     err,
		}
	}

	// Update password
	err = u.updatePassword(ctx, userData.Id, hashPassword)
	if err != nil {
		return domain.UserResetPasswordClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update password",
			Err:     err,
		}
	}

	// Mark token as inactive
	err = u.updatedPasswordResetStatus(ctx, tokenData.Id, constant.USER_PASSWORD_RESET_STATUS_INACTIVE)
	if err != nil {
		return domain.UserResetPasswordClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update token status",
			Err:     err,
		}
	}

	return domain.UserResetPasswordClientResponse{
		Message: "Password has been reset successfully",
	}, nil
}

func (u *userusecase) ValidateRefreshToken(ctx context.Context, refreshToken string) (domain.UserRefreshTokenValidateClientResponse, domain.HTTPError) {
	// Fetch token data
	userID, expiresAt, err := u.tokenEngine.GetRefreshTokenData(refreshToken)
	if err != nil {
		u.logger.Errorw(ctx, "unable to parse token",
			"event", "user_refresh_token_validation_failed",
			"token", refreshToken,
			"error", err,
		)
		return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Unable to parse token",
			Err:     err,
		}
	}

	// Validate user ID and token expiration
	if userID == 0 || expiresAt.Before(time.Now()) {
		u.logger.Warnw(ctx, "incorrect or expired token",
			"event", "user_refresh_token_validation_failed",
			"token", refreshToken,
		)
		return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Token is incorrect or expired",
			Err:     nil,
		}
	}

	// Fetch refresh token data
	refreshData, err := u.getRefreshTokenData(ctx, userID, refreshToken)
	if err != nil || refreshData.Id == 0 || refreshData.Revoked {
		u.logger.Warnw(ctx, "revoked or incorrect refresh token",
			"event", "user_refresh_token_validation_failed",
			"token", refreshToken,
		)
		return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Token is revoked or incorrect",
			Err:     nil,
		}
	}

	// Fetch user data
	userData, err := u.getUserByUserid(ctx, userID)
	if err != nil || userData.Status != constant.USER_STATUS_ACTIVE {
		u.logger.Warnw(ctx, "invalid user status",
			"event", "user_refresh_token_validation_failed",
			"userId", userID,
			"error", err,
		)
		return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Account is not active",
			Err:     nil,
		}
	}

	// Token creation
	accessToken, err := u.tokenEngine.CreateAccessToken(userData.Id, userData.Username, userData.Name, u.getAccessTokenExpiry())
	if err != nil {
		return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to create access token",
			Err:     err,
		}
	}

	// Handle refresh token rotation
	var refreshTokenType, finalRefreshToken string
	if u.refreshTokenRotationEnabled() {
		refreshTokenType = constant.REFRESH_TOKEN_TYPE_ROTATING
		err := u.revokedRefreshToken(ctx, userID, refreshToken)
		if err != nil {
			return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Failed to revoke old token",
				Err:     err,
			}
		}

		finalRefreshToken, err = u.tokenEngine.CreateRefreshToken(userID, u.getRefreshTokenExpiry())
		if err != nil {
			return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Failed to create refresh token",
				Err:     err,
			}
		}

		_, err = u.storeRefreshToken(ctx, userID, finalRefreshToken, u.getRefreshTokenExpiry())
		if err != nil {
			return domain.UserRefreshTokenValidateClientResponse{}, HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Failed to store refresh token",
				Err:     err,
			}
		}
	} else {
		refreshTokenType = constant.REFRESH_TOKEN_TYPE_STATIC
		finalRefreshToken = refreshToken
	}

	return domain.UserRefreshTokenValidateClientResponse{
		AccessToken:      accessToken,
		RefreshTokenType: refreshTokenType,
		RefreshToken:     finalRefreshToken,
	}, nil
}
