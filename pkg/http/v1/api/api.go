package api

import (
	"mayilon/pkg/middleware"
	"mayilon/pkg/service"
)

type Api struct {
	Services       service.List
	Authentication middleware.Authn
}

func New(svcList service.List, authnIns middleware.Authn) *Api {
	return &Api{
		Services:       svcList,
		Authentication: authnIns,
	}
}
