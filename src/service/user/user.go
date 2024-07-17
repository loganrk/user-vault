package user

import (
	"context"
	"mayilon/src/service"
	"mayilon/src/types"

	"mayilon/src/store"
	"time"
)

type userService struct {
	store store.User
	conf
}

type conf struct {
	LoginAttemptSessionTime          int // in seconds
	MaxLoginAttemptAllowedPerSession int
}

func New(userStoreIns store.User) service.User {
	return &userService{
		store: userStoreIns,
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
	sesstionStartTime := time.Now().Add(time.Duration(u.conf.LoginAttemptSessionTime*-1) * time.Second)
	attempCount, err := u.store.GetUserLoginAttemptCount(ctx, userId, sesstionStartTime)
	if err != nil {

		return types.LOGIN_ATTEMPT_NOT_PROCEED
	}

	if attempCount >= u.conf.MaxLoginAttemptAllowedPerSession {

		return types.LOGIN_ATTEMPT_MAX_REACHED
	}

	err = u.store.CreateUserLoginAttempt(ctx, types.UserLoginAttempt{
		UserId:    userId,
		Timestamp: int(time.Now().UnixMilli()),
	})

	if err != nil {
		return types.LOGIN_ATTEMPT_NOT_PROCEED
	}

	return types.LOGIN_ATTEMPT_PROCEED
}

func (u *userService) GetUserDataFromUsernameAndPassword(ctx context.Context, username, password string) types.User {
	userData, err := u.store.GetUserByUsernamePassword(ctx, username, password)
	if err != nil {

	}
	return userData
}
