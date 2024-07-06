package user

import (
	"mayilon/src/service"
	"mayilon/src/store"
)

type userService struct {
	store store.User
}

func New(userStoreIns store.User) service.User {
	return &userService{
		store: userStoreIns,
	}
}
