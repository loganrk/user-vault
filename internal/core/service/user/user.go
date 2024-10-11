package user

import (
	"context"
	"mayilon/config"
	"mayilon/internal/adapters"
	"mayilon/internal/core/constant"
	"mayilon/internal/core/domain"
	"mayilon/internal/utils"

	"golang.org/x/crypto/bcrypt"

	"time"
)

type userService struct {
	appName string
	logger  adapters.Logger
	mysql   adapters.RepositoryMySQL
	conf    config.User
}

func New(loggerIns adapters.Logger, mysqlIns adapters.RepositoryMySQL, appName string, userConfIns config.User) domain.UserSvr {
	return &userService{
		mysql:  mysqlIns,
		logger: loggerIns,
		conf:   userConfIns,
	}
}

func (u *userService) GetUserByUserid(ctx context.Context, userid int) (domain.User, error) {
	userData, err := u.mysql.GetUserByUserid(ctx, userid)
	return userData, err
}

func (u *userService) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	userData, err := u.mysql.GetUserByUsername(ctx, username)
	return userData, err
}

func (u *userService) CheckLoginFailedAttempt(ctx context.Context, userId int) (int, error) {
	// TODO: add client based token
	sesstionStartTime := time.Now().Add(time.Duration(u.conf.GetLoginAttemptSessionPeriod()*-1) * time.Second)
	attempCount, err := u.mysql.GetUserLoginFailedAttemptCount(ctx, userId, sesstionStartTime)
	if err != nil {

		return constant.LOGIN_ATTEMPT_FAILED, err
	}

	if attempCount >= u.conf.GetMaxLoginAttempt() {

		return constant.LOGIN_ATTEMPT_MAX_REACHED, nil
	}

	return constant.LOGIN_ATTEMPT_SUCCESS, nil
}

func (u *userService) CreateLoginAttempt(ctx context.Context, userId int, success bool) (int, error) {

	loginAttemptId, err := u.mysql.CreateUserLoginAttempt(ctx, domain.UserLoginAttempt{
		UserId:    userId,
		Success:   success,
		CreatedAt: time.Now(),
	})

	return loginAttemptId, err
}

func (u *userService) CheckPassword(ctx context.Context, password string, passwordHash string, saltHash string) (bool, error) {

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password+saltHash))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (u *userService) CreateUser(ctx context.Context, username, password, name string) (int, error) {

	saltHash, err := u.newSaltHash()
	if err != nil {
		return 0, err
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		return 0, err
	}

	var userData = domain.User{
		Username: username,
		Password: string(hashPassword),
		Salt:     saltHash,
		Name:     name,
		State:    constant.USER_STATE_INITIAL,
		Status:   constant.USER_STATUS_PENDING,
	}

	userid, err := u.mysql.CreateUser(ctx, userData)
	if err != nil {
		return 0, err
	}

	return userid, nil
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
