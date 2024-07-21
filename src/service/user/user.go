package user

import (
	"context"
	"mayilon/config"
	"mayilon/src/service"
	"mayilon/src/utils"

	"mayilon/src/types"

	"golang.org/x/crypto/bcrypt"

	"mayilon/src/store"
	"time"
)

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
}

func New(userStoreIns store.User, appName string, userConfIns config.User) service.User {
	return &userService{
		store: userStoreIns,
		conf: conf{
			maxLoginAttempt:           userConfIns.GetMaxLoginAttempt(),
			loginAttemptSessionPeriod: userConfIns.GetLoginAttemptSessionPeriod(),
			passwordHashCost:          userConfIns.GetPasswordHashCost(),
			activationLink:            userConfIns.GetActivationLink(),
			activationLinkExpiry:      userConfIns.GetActivationLinkExpiry(),
			activationTemplatePath:    userConfIns.GetActivationEmailTemplate(),
		},
	}
}

func (u *userService) GetUserByUserid(ctx context.Context, userid int) types.User {
	userData, err := u.store.GetUserByUserid(ctx, userid)
	if err != nil {

		return types.User{}
	}
	return userData
}

func (u *userService) GetUserByUsername(ctx context.Context, username string) types.User {
	userData, err := u.store.GetUserByUsername(ctx, username)
	if err != nil {

		return types.User{}
	}
	return userData
}

func (u *userService) CheckLoginAttempt(ctx context.Context, userId int) int {
	// TODO: add client based token
	sesstionStartTime := time.Now().Add(time.Duration(u.conf.loginAttemptSessionPeriod*-1) * time.Second)
	attempCount, err := u.store.GetUserLoginAttemptCount(ctx, userId, sesstionStartTime)
	if err != nil {

		return types.LOGIN_ATTEMPT_FAILED
	}

	if attempCount >= u.conf.maxLoginAttempt {

		return types.LOGIN_ATTEMPT_MAX_REACHED
	}

	return types.LOGIN_ATTEMPT_SUCCESS
}

func (u *userService) CreateLoginAttempt(ctx context.Context, userId int, success bool) int {

	loginAttemptId, err := u.store.CreateUserLoginAttempt(ctx, types.UserLoginAttempt{
		UserId:    userId,
		Success:   success,
		Timestamp: time.Now().UnixMilli(),
	})

	if err != nil {

	}

	return loginAttemptId
}

func (u *userService) GetUserByUseridAndPassword(ctx context.Context, userid int, password string, saltHash string) types.User {
	hashPassword, err := u.getHashPassword(password + saltHash)
	if err != nil {
		return types.User{}
	}

	userData, err := u.store.GetUserByUseridAndPassword(ctx, userid, string(hashPassword))
	if err != nil {

		return types.User{}
	}
	return userData
}

func (u *userService) CreateUser(ctx context.Context, username, password, name string) int {

	saltHash, err := u.newSaltHash()
	if err != nil {
		return 0
	}
	hashPassword, err := u.getHashPassword(password + saltHash)
	if err != nil {
		return 0
	}

	var userData = types.User{
		Username: username,
		Password: string(hashPassword),
		Salt:     saltHash,
		Name:     name,
		State:    types.USER_STATUS_PENDING,
		Status:   types.USER_STATE_INITIAL,
	}

	userid, err := u.store.CreateUser(ctx, userData)
	if err != nil {

	}

	return userid
}

func (u *userService) getHashPassword(password string) ([]byte, error) {

	return bcrypt.GenerateFromPassword([]byte(password), u.passwordHashCost)

}

func (u *userService) newSaltHash() (string, error) {
	// Generate a random salt (using bcrypt's salt generation function)
	saltRaw := utils.GenerateRandomString(10)

	salt, err := bcrypt.GenerateFromPassword([]byte(saltRaw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(salt), nil
}
