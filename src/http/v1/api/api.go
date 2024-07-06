package api

import (
	"mayilon/src/service"
)

type Api struct {
	Services service.List
}

func New(svcList service.List) *Api {
	return &Api{
		Services: svcList,
	}
}
