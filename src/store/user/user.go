package user

import (
	"mayilon/config"
	"mayilon/src/store"
	"mayilon/src/types"

	"gorm.io/gorm"
)

type userStore struct {
	db *gorm.DB
	//cache heap.Cache
	tables
}

type tables struct {
	user string
}

func New(appConfigIns config.App, dbIns *gorm.DB) store.User {
	return &userStore{
		db: dbIns,
		tables: tables{
			user: appConfigIns.GetStoreDatabaseTableUser(),
		},
	}
}

func (s *userStore) CreateUser(userData types.User) error {
	return s.db.Table(s.tables.user).Create(&userData).Error
}

func (s *userStore) GetUserByID(id int) (types.User, error) {
	var userData types.User
	err := s.db.Table(s.tables.user).First(&userData, id).Error
	return userData, err
}

func (s *userStore) GetUserByUsernamePassword(username, password string) (types.User, error) {
	var userData types.User
	err := s.db.Table(s.tables.user).Where("username = ? && password = ?", username, password).First(&userData).Error
	return userData, err
}
