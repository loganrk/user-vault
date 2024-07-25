package user

import (
	"context"
	"mayilon/src/types"
	"time"

	"gorm.io/gorm"
)

func (s *userStore) CreatePasswordReset(ctx context.Context, passwordResetData types.UserPasswordReset) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userPasswordReset).Create(&passwordResetData)
	return passwordResetData.Id, result.Error
}

func (s *userStore) GetPasswordResetByToken(ctx context.Context, token string) (types.UserPasswordReset, error) {
	var passwordResetData types.UserPasswordReset

	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userPasswordReset).Select("id", "user_id", "expired_at", "status").Where("token = ?", token).First(&passwordResetData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	return passwordResetData, result.Error
}

func (s *userStore) GetActivePasswordResetByUserId(ctx context.Context, userid int) (types.UserPasswordReset, error) {
	var passwordResetData types.UserPasswordReset

	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userPasswordReset).Select("id", "user_id", "expired_at", "status").Where("userid = ? and expired_at > ? and status = ?", userid, time.Now(), types.USER_PASSWORD_RESET_STATUS_ACTIVE).First(&passwordResetData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return passwordResetData, result.Error
}

func (s *userStore) UpdatedPasswordResetStatus(ctx context.Context, id int, status int) error {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userPasswordReset).Where("id = ?", id).Update("status", status)
	return result.Error

}

func (s *userStore) UpdatePassword(ctx context.Context, userid int, password string) error {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.user).Where("id = ?", userid).Update("password", password)
	return result.Error
}
