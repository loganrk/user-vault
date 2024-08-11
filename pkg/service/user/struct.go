package user

import (
	"mayilon/pkg/config"
	"mayilon/pkg/lib/logger"
	"mayilon/pkg/store"
)

type userService struct {
	appName string
	logger  logger.Logger
	store   store.User
	conf    config.User
}
