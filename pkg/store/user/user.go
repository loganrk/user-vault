package user

import (
	"context"
	"mayilon/pkg/config"
	"mayilon/pkg/store"
	"mayilon/pkg/types"
	"time"

	"github.com/loganrk/go-db"

	"gorm.io/gorm"
)

func New(tableConfigIns config.Table, dbIns db.DB) store.User {
	return &userStore{
		db:     dbIns,
		tables: tableConfigIns,
	}
}

func (s *userStore) CreateUser(ctx context.Context, userData types.User) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUser()).Create(&userData)
	return userData.Id, result.Error
}

func (s *userStore) GetUserByUserid(ctx context.Context, userid int) (types.User, error) {
	var userData types.User
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUser()).Select("id", "username", "name", "state", "status").First(&userData, userid)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userData, result.Error
}

func (s *userStore) GetUserByUsername(ctx context.Context, username string) (types.User, error) {
	var userData types.User
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUser()).Select("id", "password", "salt", "state", "status").Where("username = ?", username).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userData, result.Error
}

func (s *userStore) GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error) {
	var userLoginAttempt []types.UserLoginAttempt
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUserLoginAttemp()).Select("id").Where("user_id = ? && success = ? && created_at >= ?", userId, types.LOGIN_ATTEMPT_FAILED, sessionStartTime).Find(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	if result.Error != nil {

	}

	return int(result.RowsAffected), nil
}

func (s *userStore) CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.GetUserLoginAttemp()).Create(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userLoginAttempt.Id, result.Error
}
