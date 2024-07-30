package handler

import (
	"mayilon/pkg/middleware"
	"mayilon/pkg/service"
)

type Handler struct {
	Services       service.List
	Authentication middleware.Authn
}

func New(svcList service.List, authnIns middleware.Authn) *Handler {
	return &Handler{
		Services:       svcList,
		Authentication: authnIns,
	}
}
