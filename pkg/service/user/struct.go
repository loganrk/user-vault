package user

import (
	"mayilon/pkg/config"
	"mayilon/pkg/store"
)

type userService struct {
	appName string
	store   store.User
	conf    config.User
}
