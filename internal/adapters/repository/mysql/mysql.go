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
	m.dialer.AutoMigrate(&domain.User{}, &domain.UserLoginAttempt{}, &domain.UserTokens{})
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
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status").First(&userData, userID)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserByEmail retrieves a user record by their email.
func (m *MySQL) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status").Where("email = ?", email).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserByPhone retrieves a user record by their phone.
func (m *MySQL) GetUserByPhone(ctx context.Context, phone string) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status").Where("phone = ?", phone).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserByEmail retrieves a user record by their phone or email.
func (m *MySQL) GetUserByEmailOrPhone(ctx context.Context, email, phone string) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status").Where("email = ? or phone = ?", email, phone).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserPasswordByUserID retrieves a user record by their userID.
func (m *MySQL) GetUserPasswordByUserID(ctx context.Context, userID int) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "password", "salt").Where("id =? ", userID).First(&userData)
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

func (m *MySQL) UpdateEmailVerfied(ctx context.Context, userID int) error {
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Where("id = ?", userID).Update("email_verfied", true)
	return result.Error
}

func (m *MySQL) UpdatePhoneVerfied(ctx context.Context, userID int) error {
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Where("id = ?", userID).Update("phone_verfied", true)
	return result.Error
}

// CreateToken creates a new user verify token record.
func (m *MySQL) CreateToken(ctx context.Context, tokenData domain.UserTokens) (int, error) {
	// Create and store new token record
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Create(&tokenData)
	return tokenData.Id, result.Error
}

// GetUserToken retrieves the data for a specific token.
func (m *MySQL) GetUserToken(ctx context.Context, tokenType int8, token string) (domain.UserTokens, error) {
	var tokenData domain.UserTokens
	// Query the refresh token data by token value
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Select("id", "user_id", "expires_at", "revoked").Where("type = ? and token = ?", tokenType, token).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no token found
	}
	return tokenData, result.Error
}

func (m *MySQL) GetUserLastTokenByUserId(ctx context.Context, tokenType int8, userId int) (domain.UserTokens, error) {
	var tokenData domain.UserTokens
	// Query the refresh token data by token value
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Select("id", "user_id", "expires_at", "revoked").Where("type = ? and user_id = ?", tokenType, userId).Last(&tokenData)

	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no token found
	}
	return tokenData, result.Error
}

// RevokeToken marks a token as revoked in the database.
func (m *MySQL) RevokeToken(ctx context.Context, id int) error {
	// Mark the specified token as revoked for the user
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Where("id = ?", id).Update("revoked", true)
	return result.Error
}

// RevokeAllTokens marks a token as revoked in the database.
func (m *MySQL) RevokeAllTokens(ctx context.Context, tokenType int8, userID int) error {
	// Mark the specified token as revoked for the user
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Where("type = ? and user_id", tokenType, userID).Update("revoked", true)
	return result.Error
}
