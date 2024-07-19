package user

import (
	"context"
	"fmt"
	"mayilon/config"
	"mayilon/src/store"
	"mayilon/src/types"
	"time"

	"gorm.io/gorm"
)

type userStore struct {
	db *gorm.DB
	//cache heap.Cache
	tables
}

type tables struct {
	user             string
	userLoginAttempt string
}

func New(tableConfigIns config.Table, dbIns *gorm.DB) store.User {
	tablePrefix := tableConfigIns.GetPrefix()
	return &userStore{
		db: dbIns,
		tables: tables{
			user:             tablePrefix + tableConfigIns.GetUser(),
			userLoginAttempt: tablePrefix + tableConfigIns.GetUserLoginAttemp(),
		},
	}
}

func (s *userStore) CreateUser(ctx context.Context, userData types.User) (types.User, error) {
	result := s.db.WithContext(ctx).Table(s.tables.user).Create(&userData)
	return userData, result.Error
}

func (s *userStore) GetUserByID(ctx context.Context, id int) (types.User, error) {
	var userData types.User
	result := s.db.WithContext(ctx).Table(s.tables.user).Select("id", "state", "status").First(&userData, id)
	return userData, result.Error
}

func (s *userStore) GetUseridByUsername(ctx context.Context, username string) (int, error) {
	var userData types.User
	result := s.db.WithContext(ctx).Table(s.tables.user).Select("id").Where("username = ?", username).First(&userData)
	return userData.Id, result.Error
}

func (s *userStore) GetUserByUseridAndPassword(ctx context.Context, userid int, password string) (types.User, error) {
	var userData types.User
	result := s.db.WithContext(ctx).Table(s.tables.user).Select("id", "state", "status").Where("id = ? && password = ?", userid, password).First(&userData)
	return userData, result.Error
}

func (s *userStore) GetUserLoginAttemptCount(ctx context.Context, userId int, sessionStartTime time.Time) (int, error) {
	var userLoginAttempt []types.UserLoginAttempt
	result := s.db.WithContext(ctx).Table(s.tables.userLoginAttempt).Select("id", "timestamp").Where("user_id = ? && timestamp >= ?", userId, sessionStartTime.UnixMilli()).Find(&userLoginAttempt)
	if result.Error != nil {

	}

	return int(result.RowsAffected), nil
}

func (s *userStore) CreateUserLoginAttempt(ctx context.Context, userLoginAttempt types.UserLoginAttempt) (int, error) {
	fmt.Println(userLoginAttempt)
	result := s.db.WithContext(ctx).Table(s.tables.userLoginAttempt).Create(&userLoginAttempt)
	return userLoginAttempt.Id, result.Error
}
