package user

import (
	"mayilon/config"
	"mayilon/internal/adapters"
)

type userService struct {
	appName string
	logger  adapters.Logger
	mysql   adapters.RepositoryMySQL
	conf    config.User
}
