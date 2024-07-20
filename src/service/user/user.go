package user

import (
	"context"
	"mayilon/config"
	"mayilon/src/lib/email"
	"mayilon/src/service"

	"mayilon/src/types"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"mayilon/src/store"
	"time"
)

type userService struct {
	store store.User
	email email.Email
	conf
}
type conf struct {
	maxLoginAttempt           int
	loginAttemptSessionPeriod int
	passwordHashCost          int
}

func New(userStoreIns store.User, userConfIns config.User) service.User {
	return &userService{
		store: userStoreIns,
		conf: conf{
			maxLoginAttempt:           userConfIns.GetMaxLoginAttempt(),
			loginAttemptSessionPeriod: userConfIns.GetLoginAttemptSessionPeriod(),
			passwordHashCost:          userConfIns.GetPasswordHashCost(),
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

func (u *userService) GetUseridByUsername(ctx context.Context, username string) int {
	userid, err := u.store.GetUseridByUsername(ctx, username)
	if err != nil {

		return 0
	}
	return userid
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

func (u *userService) GetUserByUseridAndPassword(ctx context.Context, userid int, password string) types.User {
	hashPassword, err := u.getHashPassword(password)
	if err != nil {
		return types.User{}
	}

	userData, err := u.store.GetUserByUseridAndPassword(ctx, userid, string(hashPassword))
	if err != nil {

		return types.User{}
	}
	return userData
}

func (u *userService) CreateUser(ctx context.Context, username, password, name string) types.User {
	hashPassword, err := u.getHashPassword(password)
	if err != nil {
		return types.User{}
	}

	var userData = types.User{
		Username: username,
		Password: string(hashPassword),
		Name:     name,
		State:    types.USER_STATUS_PENDING,
		Status:   types.USER_STATE_INITIAL,
	}

	userData, err = u.store.CreateUser(ctx, userData)
	if err != nil {

		return types.User{}
	}

	return userData
}

func (u *userService) getHashPassword(password string) ([]byte, error) {

	return bcrypt.GenerateFromPassword([]byte(password), u.passwordHashCost)

}
