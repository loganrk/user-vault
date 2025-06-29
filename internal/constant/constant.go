package constant

const (
	LOGIN_ATTEMPT_SUCCESS     = 1
	LOGIN_ATTEMPT_MAX_REACHED = 2
	LOGIN_ATTEMPT_FAILED      = 3

	USER_STATUS_ACTIVE   = 1
	USER_STATUS_INACTIVE = 2
	USER_STATUS_PENDING  = 3
	USER_STATUS_BANNED   = 4

	USER_PASSWORD_RESET_STATUS_ACTIVE   = 1
	USER_PASSWORD_RESET_STATUS_INACTIVE = 2

	USER_STATE_INITIAL = 1

	USER_ACTIVATION_TOKEN_STATUS_ACTIVE   = 1
	USER_ACTIVATION_TOKEN_STATUS_INACTIVE = 2

	REFRESH_TOKEN_TYPE_ROTATING = "rotating"
	REFRESH_TOKEN_TYPE_STATIC   = "static"

	TOKEN_TYPE_REFRESH int8 = 1

	TOKEN_TYPE_ACTIVATION_EMAIL int8 = 2
	TOKEN_TYPE_ACTIVATION_PHONE int8 = 3

	TOKEN_TYPE_PASSWORD_RESET_EMAIL int8 = 4
	TOKEN_TYPE_PASSWORD_RESET_PHONE int8 = 5
)

const (
	USER_ACTIVATION_EMAIL_SUBJECT     = "Activate your account"
	USER_PASSWORD_RESET_EMAIL_SUBJECT = "Password reset request"
)

const (
	MessageInternalServerError  = "internal server error"
	MessageInvalidApiParameters = "invalid api parameters"

	DBException               = "DBException"
	ValidationException       = "ValidationException"
	NetworkException          = "NetworkException"
	TimeoutException          = "TimeoutException"
	TokenException            = "TokenException"
	AuthenticationException   = "AuthenticationException"
	AuthorizationException    = "AuthorizationException"
	ResourceNotFoundException = "ResourceNotFoundException"
	ForbiddenException        = "ForbiddenException"
	GenericException          = "GenericException"
)

const (
	TOKEN_MACRO = "{{token}}"
)
