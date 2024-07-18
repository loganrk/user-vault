package user

import (
	"context"
	"mayilon/config"
	"mayilon/src/service"
	"mayilon/src/types"
	"strconv"

	"mayilon/src/store"
	"time"
)

type userService struct {
	store store.User
	conf
}
type conf struct {
	maxLoginAttempt           int
	loginAttemptSessionPeriod int
}

func New(userStoreIns store.User, userConfIns config.User) service.User {
	return &userService{
		store: userStoreIns,
		conf: conf{
			maxLoginAttempt:           userConfIns.GetMaxLoginAttempt(),
			loginAttemptSessionPeriod: userConfIns.GetLoginAttemptSessionPeriod(),
		},
	}
}

func (u *userService) GetUserIdFromUsername(ctx context.Context, username string) int {
	userData, err := u.store.GetUserByUsername(ctx, username)
	if err != nil {
	}
	return userData.Id
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

	loginAttemptId, err := u.store.CreateUserLoginAttempt(ctx, types.UserLoginAttempt{
		UserId:    userId,
		Timestamp: time.Now().UnixMilli(),
	})

	if err != nil {
		ctx = context.WithValue(ctx, "loginAttemptId", strconv.Itoa(loginAttemptId))

		return types.LOGIN_ATTEMPT_FAILED
	}

	return types.LOGIN_ATTEMPT_SUCCESS
}

func (u *userService) GetUserDataFromUsernameAndPassword(ctx context.Context, username, password string) types.User {
	userData, err := u.store.GetUserByUsernamePassword(ctx, username, password)
	if err != nil {

	}
	return userData
}
