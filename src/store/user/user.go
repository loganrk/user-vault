package user

import (
	"context"
	"mayilon/config"
	"mayilon/src/lib/db"
	"mayilon/src/store"
	"mayilon/src/types"
	"time"

	"gorm.io/gorm"
)

type userStore struct {
	db db.DB
	//cache heap.Cache
	tables
}

type tables struct {
	user                string
	userLoginAttempt    string
	userActivationToken string
}

func New(tableConfigIns config.Table, dbIns db.DB) store.User {
	tablePrefix := tableConfigIns.GetPrefix()
	return &userStore{
		db: dbIns,
		tables: tables{
			user:                tablePrefix + tableConfigIns.GetUser(),
			userLoginAttempt:    tablePrefix + tableConfigIns.GetUserLoginAttemp(),
			userActivationToken: tablePrefix + tableConfigIns.GetUserActivationToken(),
		},
	}
}

func (s *userStore) CreateUser(ctx context.Context, userData types.User) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.user).Create(&userData)
	return userData.Id, result.Error
}

func (s *userStore) GetUserByUserid(ctx context.Context, userid int) (types.User, error) {
	var userData types.User
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.user).Select("id", "username", "name", "state", "status").First(&userData, userid)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userData, result.Error
}

func (s *userStore) GetUserByUsername(ctx context.Context, username string) (types.User, error) {
	var userData types.User
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.user).Select("id", "password", "salt", "status").Where("username = ?", username).First(&userData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userData, result.Error
}

func (s *userStore) GetUserLoginFailedAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error) {
	var userLoginAttempt []types.UserLoginAttempt
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userLoginAttempt).Select("id").Where("user_id = ? && success = ? && created_at >= ?", userId, types.LOGIN_ATTEMPT_FAILED, sessionStartTime).Find(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	if result.Error != nil {

	}

	return int(result.RowsAffected), nil
}

func (s *userStore) CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userLoginAttempt).Create(&userLoginAttempt)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}
	return userLoginAttempt.Id, result.Error
}

func (s *userStore) GetActivationTokenIdByToken(ctx context.Context, token string) (int, error) {
	var tokenData types.UserActivationToken

	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userActivationToken).Select("id").Where("token = ?", token).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	return tokenData.Id, result.Error
}

func (s *userStore) CreateActivationToken(ctx context.Context, tokenData types.UserActivationToken) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userActivationToken).Create(&tokenData)
	return tokenData.Id, result.Error
}
func (s *userStore) GetPasswordResetTokenIdByToken(ctx context.Context, token string) (int, error) {
	var tokenData types.UserPasswordReset

	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userActivationToken).Select("id").Where("token = ?", token).First(&tokenData)
	if result.Error == gorm.ErrRecordNotFound {
		result.Error = nil
	}

	return tokenData.Id, result.Error
}

func (s *userStore) CreatePasswordResetToken(ctx context.Context, tokenData types.UserPasswordReset) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userActivationToken).Create(&tokenData)
	return tokenData.Id, result.Error
}
