package mysql

import (
	"context"

	"github.com/loganrk/user-vault/internal/constant"
	"github.com/loganrk/user-vault/internal/core/domain"

	gormMysql "gorm.io/driver/mysql"

	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// mysql struct represents the mySql database connection using GORM ORM.
type mySql struct {
	dialer *gorm.DB // GORM DB instance for handling database operations
}

// New initializes a new mySql repository with the given connection details.
func New(hostname, port, username, password, name, prefix string) (*mySql, error) {
	// Build Data Source Name (DSN) for connecting to mySql database
	dsn := username + ":" + password + "@tcp(" + hostname + ":" + port + ")/" + name + "?charset=utf8mb4&parseTime=True&loc=Local"
	// Open a connection to mySql using GORM with error logging and table prefix
	dialer, err := gorm.Open(gormMysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error), // Log only errors
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: prefix, // Prefix for table names
		},
	})
	return &mySql{
		dialer: dialer, // Initialize mySql repository
	}, err
}

// AutoMigrate auto-migrates the specified domain models to the database schema.
func (m *mySql) AutoMigrate() {
	// Migrate multiple domain models to ensure schema consistency
	m.dialer.AutoMigrate(&domain.User{}, &domain.UserLoginAttempt{}, &domain.UserTokens{})
}

// CreateUser creates a new user record in the database.
func (m *mySql) CreateUser(ctx context.Context, userData domain.User) (int, error) {
	// Create a new user and return the ID after creation
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Create(&userData)
	return userData.Id, result.Error
}

func (m *mySql) CreateOauthAccount(ctx context.Context, accountData domain.OAuthAccount) (int, error) {
	// Create a new account and return the ID after creation
	result := m.dialer.WithContext(ctx).Model(&domain.OAuthAccount{}).Create(&accountData)
	return accountData.Id, result.Error
}

// GetUserByUserID retrieves a user record by their user ID.
func (m *mySql) GetUserByUserID(ctx context.Context, userID int) (domain.User, error) {
	var userData domain.User
	// Select specific user fields to reduce data fetching overhead
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status").First(&userData, userID)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserByEmail retrieves a user record by their email.
func (m *mySql) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status").Where("email = ?", email).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetOauthAccountForProvider retrieves an OAuth account by provider, providerId, userId, or email.
func (m *mySql) GetOauthAccountForProvider(ctx context.Context, userId int, email string, provider domain.OAuthID, providerId string) (domain.OAuthAccount, error) {

	var account domain.OAuthAccount

	// Build GORM query
	result := m.dialer.WithContext(ctx).
		Model(&domain.OAuthAccount{}).
		Select("id", "user_id", "email", "provider", "provider_id").
		Where("provider = ? and provider_id = ? and user_id = ? and email = ?)",
			provider, providerId, userId, email).
		First(&account)

	// If not found, return nil error but empty account
	if result.Error == gorm.ErrRecordNotFound {
		return account, nil
	}

	return account, result.Error
}

// GetUserByPhone retrieves a user record by their phone.
func (m *mySql) GetUserByPhone(ctx context.Context, phone string) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status").Where("phone = ?", phone).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserByEmailOrPhone retrieves a user record by their phone or email.
func (m *mySql) GetUserByEmailOrPhone(ctx context.Context, email, phone string) (domain.User, error) {
	var userData domain.User

	// If both email and phone are empty, no need to query
	if email == "" && phone == "" {
		return userData, nil
	}

	query := m.dialer.WithContext(ctx).Model(&domain.User{}).
		Select("id", "email", "email_verified", "phone", "phone_verified", "name", "state", "status")

	// Apply conditions based on which field is present
	if email != "" && phone != "" {
		query = query.Where("email = ? OR phone = ?", email, phone)
	} else if email != "" {
		query = query.Where("email = ?", email)
	} else if phone != "" {
		query = query.Where("phone = ?", phone)
	}

	result := query.First(&userData)

	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // No user found is not an error
	}

	return userData, result.Error

}

// GetUserPasswordByUserID retrieves a user record by their userID.
func (m *mySql) GetUserPasswordByUserID(ctx context.Context, userID int) (domain.User, error) {
	var userData domain.User
	// Select specific fields for user data fetching
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Select("id", "password").Where("id =? ", userID).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no user found
	}
	return userData, result.Error
}

// GetUserLoginFailedAttemptCount counts the number of failed login attempts by the user.
func (m *mySql) GetUserLoginFailedAttemptCount(ctx context.Context, userID int, sessionStartTime time.Time) (int, error) {
	var userLoginAttempt []domain.UserLoginAttempt
	// Query failed login attempts for the user after a specified start time
	result := m.dialer.WithContext(ctx).Model(&domain.UserLoginAttempt{}).Select("id").Where("user_id = ? && success = ? && created_at >= ?", userID, constant.LOGIN_ATTEMPT_FAILED, sessionStartTime).Find(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no failed attempts found
	}
	return int(result.RowsAffected), nil
}

// CreateUserLoginAttempt records a new failed login attempt for the user.
func (m *mySql) CreateUserLoginAttempt(ctx context.Context, userLoginAttempt domain.UserLoginAttempt) (int, error) {
	// Create a new login attempt record and return the generated ID
	result := m.dialer.WithContext(ctx).Model(&domain.UserLoginAttempt{}).Create(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no record found
	}
	return userLoginAttempt.Id, result.Error
}

// UpdatePassword updates the password for a user identified by their user ID.
func (m *mySql) UpdatePassword(ctx context.Context, userID int, password string) error {
	// Update the password field for the user with the given userID
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Where("id = ?", userID).Update("password", password)

	// Check if an error occurred during the update
	if result.Error != nil {
		return result.Error
	}

	// Return nil if the password was updated successfully
	return nil
}

func (m *mySql) UpdateEmailVerfied(ctx context.Context, userID int) error {
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Where("id = ?", userID).Update("email_verified", true)
	return result.Error
}

func (m *mySql) UpdatePhoneVerfied(ctx context.Context, userID int) error {
	result := m.dialer.WithContext(ctx).Model(&domain.User{}).Where("id = ?", userID).Update("phone_verified", true)
	return result.Error
}

// CreateToken creates a new user verify token record.
func (m *mySql) CreateToken(ctx context.Context, tokenData domain.UserTokens) (int, error) {
	// Create and store new token record
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Create(&tokenData)
	return tokenData.Id, result.Error
}

// GetUserToken retrieves the data for a specific token.
func (m *mySql) GetUserToken(ctx context.Context, tokenType int8, token string) (domain.UserTokens, error) {
	var tokenData domain.UserTokens
	// Query the refresh token data by token value
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Select("id", "user_id", "expires_at", "revoked").Where("type = ? and token = ?", tokenType, token).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no token found
	}
	return tokenData, result.Error
}

func (m *mySql) GetUserLastTokenByUserId(ctx context.Context, tokenType int8, userId int) (domain.UserTokens, error) {
	var tokenData domain.UserTokens
	// Query the refresh token data by token value
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Select("id", "user_id", "token", "expires_at", "revoked").Where("type = ? and user_id = ?", tokenType, userId).Last(&tokenData)

	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil // Return nil error if no token found
	}
	return tokenData, result.Error
}

// RevokeToken marks a token as revoked in the database.
func (m *mySql) RevokeToken(ctx context.Context, id int) error {
	// Mark the specified token as revoked for the user
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Where("id = ?", id).Update("revoked", true)
	return result.Error
}

// RevokeAllTokens marks a token as revoked in the database.
func (m *mySql) RevokeAllTokens(ctx context.Context, tokenType int8, userID int) error {
	// Mark the specified token as revoked for the user
	result := m.dialer.WithContext(ctx).Model(&domain.UserTokens{}).Where("type = ? and user_id =?", tokenType, userID).Update("revoked", true)
	return result.Error
}
