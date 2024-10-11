package mysql

import (
	"context"
	"mayilon/internal/adapters"
	"mayilon/internal/core/constant.go"
	"mayilon/internal/core/domain"

	"time"

	"github.com/loganrk/go-db"

	"gorm.io/gorm"
)

type mysql struct {
	dbIns db.DB
}

func New(dbIns db.DB) adapters.RepositoryMySQL {
	return &mysql{
		dbIns: dbIns,
	}
}
func (m *mysql) AutoMigrate() {
	m.dbIns.GetDb().AutoMigrate(&domain.User{}, &domain.UserLoginAttempt{}, &domain.UserActivationToken{}, &domain.UserPasswordReset{}, &domain.UserRefreshToken{})

}

func (m *mysql) CreateUser(ctx context.Context, userData domain.User) (int, error) {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.User{}).Create(&userData)
	return userData.Id, result.Error
}

func (m *mysql) GetUserByUserid(ctx context.Context, userid int) (domain.User, error) {
	var userData domain.User
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.User{}).Select("id", "username", "name", "state", "status").First(&userData, userid)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userData, result.Error
}

func (m *mysql) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	var userData domain.User
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.User{}).Select("id", "password", "salt", "state", "status").Where("username = ?", username).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userData, result.Error
}

func (m *mysql) GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error) {
	var userLoginAttempt []domain.UserLoginAttempt
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserLoginAttempt{}).Select("id").Where("user_id = ? && success = ? && created_at >= ?", userId, constant.LOGIN_ATTEMPT_FAILED, sessionStartTime).Find(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	if result.Error != nil {

	}

	return int(result.RowsAffected), nil
}

func (m *mysql) CreateUserLoginAttempt(ctx context.Context, userLoginAttempt domain.UserLoginAttempt) (int, error) {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserLoginAttempt{}).Create(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userLoginAttempt.Id, result.Error
}

func (m *mysql) CreateActivation(ctx context.Context, tokenData domain.UserActivationToken) (int, error) {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserActivationToken{}).Create(&tokenData)
	return tokenData.Id, result.Error
}

func (m *mysql) GetActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error) {
	var tokenData domain.UserActivationToken

	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserActivationToken{}).Select("id").Where("token = ?", token).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	return tokenData, result.Error
}

func (m *mysql) UpdatedActivationtatus(ctx context.Context, id int, status int) error {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserActivationToken{}).Where("id = ?", id).Update("status", status)
	return result.Error

}

func (m *mysql) UpdateStatus(ctx context.Context, userid int, status int) error {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserActivationToken{}).Where("id = ?", userid).Update("status", status)
	return result.Error
}

func (m *mysql) CreateRefreshToken(ctx context.Context, refreshTokenData domain.UserRefreshToken) (int, error) {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserRefreshToken{}).Create(&refreshTokenData)
	return refreshTokenData.Id, result.Error
}

func (m *mysql) RevokedRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserRefreshToken{}).Where("user_id = ? and token = ?", userid, refreshToken).Update("revoked", true)
	return result.Error

}

func (m *mysql) GetRefreshTokenData(ctx context.Context, userid int, refreshToken string) (domain.UserRefreshToken, error) {
	var tokenData domain.UserRefreshToken
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserRefreshToken{}).Select("id", "expires_at", "revoked").Where("user_id = ? and token = ?", userid, refreshToken).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	return tokenData, result.Error
}

func (m *mysql) CreatePasswordReset(ctx context.Context, passwordResetData domain.UserPasswordReset) (int, error) {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserPasswordReset{}).Create(&passwordResetData)
	return passwordResetData.Id, result.Error
}

func (m *mysql) GetPasswordResetByToken(ctx context.Context, token string) (domain.UserPasswordReset, error) {
	var passwordResetData domain.UserPasswordReset

	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserPasswordReset{}).Select("id", "user_id", "expires_at", "status").Where("token = ?", token).First(&passwordResetData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	return passwordResetData, result.Error
}

func (m *mysql) GetActivePasswordResetByUserId(ctx context.Context, userid int) (domain.UserPasswordReset, error) {
	var passwordResetData domain.UserPasswordReset

	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserPasswordReset{}).Select("id", "user_id", "expires_at", "status").Where("userid = ? and expires_at > ? and status = ?", userid, time.Now(), constant.USER_PASSWORD_RESET_STATUS_ACTIVE).First(&passwordResetData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return passwordResetData, result.Error
}

func (m *mysql) UpdatedPasswordResetStatus(ctx context.Context, id int, status int) error {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.UserPasswordReset{}).Where("id = ?", id).Update("status", status)
	return result.Error

}

func (m *mysql) UpdatePassword(ctx context.Context, userid int, password string) error {
	result := m.dbIns.GetDb().WithContext(ctx).Model(&domain.User{}).Where("id = ?", userid).Update("password", password)
	return result.Error
}
