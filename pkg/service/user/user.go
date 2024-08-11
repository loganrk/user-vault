package user

import (
	"context"
	"fmt"
	"mayilon/pkg/config"
	"mayilon/pkg/lib/logger"
	"mayilon/pkg/service"
	"mayilon/pkg/utils"

	"mayilon/pkg/types"

	"golang.org/x/crypto/bcrypt"

	"mayilon/pkg/store"
	"time"
)

func New(loggerIns logger.Logger, userStoreIns store.User, appName string, userConfIns config.User) service.User {
	return &userService{
		store:  userStoreIns,
		logger: loggerIns,
		conf:   userConfIns,
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

func (u *userService) CheckLoginFailedAttempt(ctx context.Context, userId int) int {
	// TODO: add client based token
	sesstionStartTime := time.Now().Add(time.Duration(u.conf.GetLoginAttemptSessionPeriod()*-1) * time.Second)
	attempCount, err := u.store.GetUserLoginFailedAttemptCount(ctx, userId, sesstionStartTime)
	if err != nil {

		return types.LOGIN_ATTEMPT_FAILED
	}

	if attempCount >= u.conf.GetMaxLoginAttempt() {

		return types.LOGIN_ATTEMPT_MAX_REACHED
	}

	return types.LOGIN_ATTEMPT_SUCCESS
}

func (u *userService) CreateLoginAttempt(ctx context.Context, userId int, success bool) int {

	loginAttemptId, err := u.store.CreateUserLoginAttempt(ctx, types.UserLoginAttempt{
		UserId:    userId,
		Success:   success,
		CreatedAt: time.Now(),
	})

	if err != nil {

	}

	return loginAttemptId
}

func (u *userService) CheckPassword(ctx context.Context, password string, passwordHash string, saltHash string) bool {

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password+saltHash))
	fmt.Println(err)
	if err != nil {
		return false
	}
	return true
}

func (u *userService) CreateUser(ctx context.Context, username, password, name string) int {

	saltHash, err := u.newSaltHash()
	if err != nil {
		return 0
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		return 0
	}

	var userData = types.User{
		Username: username,
		Password: string(hashPassword),
		Salt:     saltHash,
		Name:     name,
		State:    types.USER_STATE_INITIAL,
		Status:   types.USER_STATUS_PENDING,
	}

	userid, err := u.store.CreateUser(ctx, userData)
	if err != nil {

	}

	return userid
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
