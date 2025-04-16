package v1

import (
	"userVault/internal/domain"
	"userVault/internal/port"
)

type handler struct {
	usecases       domain.List
	logger         port.Logger
	tokenEngineIns port.Token
}

func New(loggerIns port.Logger, tokenEngineIns port.Token, svcList domain.List) port.Handler {
	return &handler{
		usecases:       svcList,
		logger:         loggerIns,
		tokenEngineIns: tokenEngineIns,
	}
}
