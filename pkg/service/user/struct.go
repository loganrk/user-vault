package user

import "mayilon/pkg/store"

type userService struct {
	store store.User
	conf
}
type conf struct {
	appName                   string
	maxLoginAttempt           int
	loginAttemptSessionPeriod int
	passwordHashCost          int
	activationLink            string
	activationLinkExpiry      int
	activationTemplatePath    string
	passwordResetLink         string
	passwordResetLinkExpiry   int
	passwordResetTemplatePath string
}
