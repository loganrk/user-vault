package mysql

import (
	"context"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"
	"github.com/loganrk/user-vault/internal/core/port"

	gormMysql "gorm.io/driver/mysql"

	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// mysql struct represents the MySQL database connection using GORM ORM.
type MySQL struct {
	dialer *gorm.DB // GORM DB instance for handling database operations
}

// New initializes a new MySQL repository with the given connection details.
func New(hostname, port, username, password, name, prefix string) (port.RepositoryMySQL, error) {
	// Build Data Source Name (DSN) for connecting to MySQL database
	dsn := username + ":" + password + "@tcp(" + hostname + ":" + port + ")/" + name + "?charset=utf8mb4&parseTime=True&loc=Local"
	// Open a connection to MySQL using GORM with error logging and table prefix
	dialer, err := gorm.Open(gormMysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error), // Log only errors
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: prefix, // Prefix for table names
		},
	})
	return &MySQL{
		dialer: dialer, // Initialize MySQL repository
	}, err
}

// AutoMigrate auto-migrates the specified domain models to the database schema.
func (m *MySQL) AutoMigrate() {
	// Migrate multiple domain models to ensure schema consistency
	m.dialer.AutoMigrate(&domain.User{}, &domain.UserLoginAttempt{}, &domain.UserActivationToken{}, &domain.UserPasswordReset{}, &domain.UserRefreshToken{})
}

// CreateUser creates a new user record in the database.
func (m *MySQL) CreateUser(ctx context.Context, userData domain.User) (int, error) {
	// Create a new user and return the ID after creation
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Create(&userData)
	return userData.Id, result.Error
}

// GetUserByUserID retrieves a user record by their user ID.
func (m *MySQL) GetUserByUserID(ctx context.Context, userID int) (domain.User, error) {
	var userData domain.User
	// Select specific user fields to reduce data fetching overhead
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "username", "name", "state", "status").First(&userData, userID)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserByUsername retrieves a user record by their username.
func (m *MySQL) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "password", "salt", "state", "status").Where("username = ?", username).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserByEmail retrieves a user record by their email.
func (m *MySQL) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "name", "state", "status").Where("username = ?", email).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserDetailsWithPasswordByUserID retrieves a user record by their userID.
func (m *MySQL) GetUserDetailsWithPasswordByUserID(ctx context.Context, userID int) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "password", "salt", "state", "status").Where("id = ?", userID).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserLoginFailedAttemptCount counts the number of failed login attempts by the user.
func (m *MySQL) GetUserLoginFailedAttemptCount(ctx context.Context, userID int, sessionStartTime time.Time) (int, error) {
	var userLoginAttempt []domain.UserLoginAttempt
	// Query failed login attempts for the user after a specified start time
	result := m.dialer.WithContext(ctx).Model(&domain.UserLoginAttempt{}).Select("id").Where("user_id = ? && success = ? && created_at >= ?", userID, constant.LOGIN_ATTEMPT_FAILED, sessionStartTime).Find(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no failed attempts found
	}
	return int(result.RowsAffected), nil
}

// CreateUserLoginAttempt records a new failed login attempt for the user.
func (m *MySQL) CreateUserLoginAttempt(ctx context.Context, userLoginAttempt domain.UserLoginAttempt) (int, error) {
	// Create a new login attempt record and return the generated ID
	result := m.dialer.WithContext(ctx).Model(&domain.UserLoginAttempt{}).Create(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no record found
	}
	return userLoginAttempt.Id, result.Error
}

// CreateActivation creates a new user activation token record.
func (m *MySQL) CreateActivation(ctx context.Context, tokenData domain.UserActivationToken) (int, error) {
	// Create and store new activation token record
	result := m.dialer.WithContext(ctx).Model(&domain.UserActivationToken{}).Create(&tokenData)
	return tokenData.Id, result.Error
}

// GetActivationByToken retrieves a user activation token by the token value.
func (m *MySQL) GetActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error) {
	var tokenData domain.UserActivationToken
	// Query token by its value
	result := m.dialer.WithContext(ctx).Model(&domain.UserActivationToken{}).Select("id", "user_id", "status", "expires_at").Where("token = ?", token).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no token found
	}
	return tokenData, result.Error
}

// UpdateActivationStatus updates the activation token status in the database.
func (m *MySQL) UpdateActivationStatus(ctx context.Context, id int, status int) error {
	// Update the status of a specific activation token by ID
	result := m.dialer.WithContext(ctx).Model(&domain.UserActivationToken{}).Where("id = ?", id).Update("status", status)
	return result.Error
}

// UpdateUserStatus updates the status of a user by their user ID.
func (m *MySQL) UpdateUserStatus(ctx context.Context, userID int, status int) error {
	// Update the status for the user based on their ID
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Where("id = ?", userID).Update("status", status)
	return result.Error
}

// CreateRefreshToken creates a new user refresh token record.
func (m *MySQL) CreateRefreshToken(ctx context.Context, refreshTokenData domain.UserRefreshToken) (int, error) {
	// Create a new refresh token and return the generated ID
	result := m.dialer.WithContext(ctx).Model(&domain.UserRefreshToken{}).Create(&refreshTokenData)
	return refreshTokenData.Id, result.Error
}

// RevokeRefreshToken marks a refresh token as revoked in the database.
func (m *MySQL) RevokeRefreshToken(ctx context.Context, userID int, refreshToken string) error {
	// Mark the specified refresh token as revoked for the user
	result := m.dialer.WithContext(ctx).Model(&domain.UserRefreshToken{}).Where("user_id = ? and token = ?", userID, refreshToken).Update("revoked", true)
	return result.Error
}

// GetRefreshTokenData retrieves the data for a specific refresh token.
func (m *MySQL) GetRefreshTokenData(ctx context.Context, refreshToken string) (domain.UserRefreshToken, error) {
	var tokenData domain.UserRefreshToken
	// Query the refresh token data by token value
	result := m.dialer.WithContext(ctx).Model(&domain.UserRefreshToken{}).Select("id", "user_id", "expires_at", "revoked").Where("token = ?", refreshToken).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no token found
	}
	return tokenData, result.Error
}

// CreatePasswordReset creates a new password reset record.
func (m *MySQL) CreatePasswordReset(ctx context.Context, passwordResetData domain.UserPasswordReset) (int, error) {
	// Create a new password reset record and return the ID
	result := m.dialer.WithContext(ctx).Model(&domain.UserPasswordReset{}).Create(&passwordResetData)
	return passwordResetData.Id, result.Error
}

// GetPasswordResetByToken retrieves a password reset record by its token.
func (m *MySQL) GetPasswordResetByToken(ctx context.Context, token string) (domain.UserPasswordReset, error) {
	var passwordResetData domain.UserPasswordReset
	// Query the password reset record by token
	result := m.dialer.WithContext(ctx).Model(&domain.UserPasswordReset{}).Select("id", "user_id", "expires_at", "status").Where("token = ?", token).First(&passwordResetData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no record found
	}
	return passwordResetData, result.Error
}

// GetActivePasswordResetByUserID retrieves an active password reset request for a user.
func (m *MySQL) GetActivePasswordResetByUserID(ctx context.Context, userID int) (domain.UserPasswordReset, error) {
	var passwordResetData domain.UserPasswordReset
	// Query active password reset requests by user ID
	result := m.dialer.WithContext(ctx).Model(&domain.UserPasswordReset{}).Select("id", "user_id", "expires_at", "status").Where("user_id = ? and expires_at > ? and status = ?", userID, time.Now(), constant.USER_PASSWORD_RESET_STATUS_ACTIVE).First(&passwordResetData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no active reset found
	}
	return passwordResetData, result.Error
}

// UpdatePasswordResetStatus updates the status of a password reset request.
func (m *MySQL) UpdatePasswordResetStatus(ctx context.Context, id int, status int) error {
	// Update the status of a specific password reset request
	result := m.dialer.WithContext(ctx).Model(&domain.UserPasswordReset{}).Where("id = ?", id).Update("status", status)
	return result.Error
}

// UpdatePassword updates the password for a user identified by their user ID.
func (m *MySQL) UpdatePassword(ctx context.Context, userID int, password string) error {
	// Update the password field for the user with the given userID
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Where("id = ?", userID).Update("password", password)

	// Check if an error occurred during the update
	if result.Error != nil {
		return result.Error
	}

	// Return nil if the password was updated successfully
	return nil
}

// UpdatedActivationStatus updates the status of the user activation token by its ID.
func (m *MySQL) UpdatedActivationStatus(ctx context.Context, id int, status int) error {
	// Update the status field for the user activation token with the given ID
	result := m.dialer.WithContext(ctx).Model(&domain.UserActivationToken{}).Where("id = ?", id).Update("status", status)

	// Check if an error occurred during the update
	if result.Error != nil {
		return result.Error
	}

	// Return nil if the status was updated successfully
	return nil
}
