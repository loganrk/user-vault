package handler

import (
	"mayilon/pkg/lib/logger"
	"mayilon/pkg/middleware"
	"mayilon/pkg/service"
)

type Handler struct {
	services       service.List
	logger         logger.Logger
	authentication middleware.Authn
}

func New(loggerIns logger.Logger, svcList service.List, authnIns middleware.Authn) *Handler {
	return &Handler{
		services:       svcList,
		logger:         loggerIns,
		authentication: authnIns,
	}
}
