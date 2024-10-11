package v1

import (
	"mayilon/internal/adapters"
	"mayilon/internal/core/service"
)

const (
	ERROR_CODE_INTERNAL_SERVER = "SE01"

	ERROR_CODE_REQUEST_INVALID        = "RE01"
	ERROR_CODE_REQUEST_PARAMS_INVALID = "RE02"

	ERROR_CODE_TOKEN_INCORRECT     = "TO01"
	ERROR_CODE_TOKEN_ALREADY_USED  = "TO02"
	ERROR_CODE_TOKEN_EXPIRED       = "TO03"
	ERROR_CODE_TOKEN_REVOKED       = "TO04"
	ERROR_CODE_TOKEN_NOT_AVAILABLE = "TO05"

	ERROR_CODE_ACCOUNT_ACTIVE   = "AC01"
	ERROR_CODE_ACCOUNT_INACTIVE = "AC02"
	ERROR_CODE_ACCOUNT_PENDING  = "AC03"
	ERROR_CODE_ACCOUNT_BANNED   = "AC02"

	ERROR_CODE_USERNAME_NOT_AVAILABLE         = "CA01"
	ERROR_CODE_USERNAME_INCORRECT             = "CA02"
	ERROR_CODE_USERNAME_OR_PASSWORD_INCORRECT = "CA03"
	ERROR_CODE_MAX_ATTEMPT_REACHED            = "CA04"
)

type handler struct {
	services       service.List
	logger         adapters.Logger
	tokenEngineIns adapters.Token
}

func New(loggerIns adapters.Logger, tokenEngineIns adapters.Token, svcList service.List) adapters.Handler {
	return &handler{
		services:       svcList,
		logger:         loggerIns,
		tokenEngineIns: tokenEngineIns,
	}
}
