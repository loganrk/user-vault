package user

import (
	"context"
	"mayilon/config"
	"mayilon/src/lib/db"
	"mayilon/src/store"
	"mayilon/src/types"
	"time"
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
			user:             tablePrefix + tableConfigIns.GetUser(),
			userLoginAttempt: tablePrefix + tableConfigIns.GetUserLoginAttemp(),
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
	return userData, result.Error
}

func (s *userStore) GetUserByUsername(ctx context.Context, username string) (types.User, error) {
	var userData types.User
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.user).Select("id", "salt").Where("username = ?", username).First(&userData)
	return userData, result.Error
}

func (s *userStore) GetUserByUseridAndPassword(ctx context.Context, userid int, password string) (types.User, error) {
	var userData types.User
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.user).Select("id", "state", "status").Where("id = ? && password = ?", userid, password).First(&userData)
	return userData, result.Error
}

func (s *userStore) GetUserLoginAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error) {
	var userLoginAttempt []types.UserLoginAttempt
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userLoginAttempt).Select("id", "timestamp").Where("user_id = ? && timestamp >= ?", userId, sessionStartTime.UnixMilli()).Find(&userLoginAttempt)
	if result.Error != nil {

	}

	return int(result.RowsAffected), nil
}

func (s *userStore) CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userLoginAttempt).Create(&userLoginAttempt)
	return userLoginAttempt.Id, result.Error
}

func (s *userStore) UserActivationTokenExists(ctx context.Context, token string) (bool, error) {
	var tokenData types.UserActivationToken

	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userActivationToken).Select("id").Where("token = ?", token).First(&tokenData)
	if tokenData.Id != 0 {
		return true, result.Error
	}

	return false, result.Error
}

func (s *userStore) CreateActivationToken(ctx context.Context, tokenData types.UserActivationToken) (int, error) {
	result := s.db.GetDb().WithContext(ctx).Table(s.tables.userActivationToken).Create(&tokenData)
	return tokenData.Id, result.Error
}
