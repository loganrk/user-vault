package user

import (
	"context"
	"mayilon/internal/domain"
	"time"
)

func (u *userusecase) getUserByUsername(ctx context.Context, username string) (domain.User, error) {
	userData, err := u.mysql.GetUserByUsername(ctx, username)
	return userData, err
}

func (u *userusecase) getUserByUserid(ctx context.Context, userid int) (domain.User, error) {
	userData, err := u.mysql.GetUserByUserid(ctx, userid)
	return userData, err
}

func (u *userusecase) getUserLoginFailedAttemptCount(ctx context.Context, userid int, sesstionStartTime time.Time) (int, error) {
	attempCount, err := u.mysql.GetUserLoginFailedAttemptCount(ctx, userid, sesstionStartTime)
	return attempCount, err
}

func (u *userusecase) createLoginAttempt(ctx context.Context, userId int, success bool) (int, error) {

	loginAttemptId, err := u.mysql.CreateUserLoginAttempt(ctx, domain.UserLoginAttempt{
		UserId:    userId,
		Success:   success,
		CreatedAt: time.Now(),
	})

	return loginAttemptId, err
}

func (u *userusecase) createUser(ctx context.Context, userData domain.User) (int, error) {
	userid, err := u.mysql.CreateUser(ctx, userData)
	return userid, err
}

func (u *userusecase) getActivePasswordResetByUserId(ctx context.Context, userid int) (domain.UserPasswordReset, error) {
	passwordResetData, err := u.mysql.GetActivePasswordResetByUserId(ctx, userid)
	return passwordResetData, err
}

func (u *userusecase) getPasswordResetByToken(ctx context.Context, passwordResetToken string) (domain.UserPasswordReset, error) {
	alreadyExiststData, err := u.mysql.GetPasswordResetByToken(ctx, passwordResetToken)
	return alreadyExiststData, err

}

func (u *userusecase) updatedPasswordResetStatus(ctx context.Context, id int, status int) error {
	err := u.mysql.UpdatedPasswordResetStatus(ctx, id, status)

	return err
}

func (u *userusecase) updatePassword(ctx context.Context, userid int, hashPassword []byte) error {

	err := u.mysql.UpdatePassword(ctx, userid, string(hashPassword))
	return err

}

func (u *userusecase) createRefreshToken(ctx context.Context, refreshTokenData domain.UserRefreshToken) (int, error) {

	refreshTokenId, err := u.mysql.CreateRefreshToken(ctx, refreshTokenData)
	return refreshTokenId, err

}

func (u *userusecase) revokedRefreshToken(ctx context.Context, userid int, refreshToken string) error {
	err := u.mysql.RevokedRefreshToken(ctx, userid, refreshToken)

	return err
}

func (u *userusecase) getRefreshTokenData(ctx context.Context, userid int, refreshToken string) (domain.UserRefreshToken, error) {
	tokenData, err := u.mysql.GetRefreshTokenData(ctx, userid, refreshToken)

	return tokenData, err

}

func (u *userusecase) getActivationByToken(ctx context.Context, activationToken string) (domain.UserActivationToken, error) {
	tokenData, err := u.mysql.GetActivationByToken(ctx, activationToken)
	return tokenData, err

}

func (u *userusecase) createActivation(ctx context.Context, tokenData domain.UserActivationToken) (int, error) {
	tokenId, err := u.mysql.CreateActivation(ctx, tokenData)
	return tokenId, err

}

func (u *userusecase) getUserActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error) {
	tokenData, err := u.mysql.GetActivationByToken(ctx, token)
	return tokenData, err
}

func (u *userusecase) updatedActivationtatus(ctx context.Context, id int, status int) error {
	err := u.mysql.UpdatedActivationtatus(ctx, id, status)

	return err
}

func (u *userusecase) updateStatus(ctx context.Context, userid int, status int) error {
	err := u.mysql.UpdateStatus(ctx, userid, status)
	return err
}

func (u *userusecase) getAccessTokenExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetAccessTokenExpiry()) * time.Second)
}

func (u *userusecase) refreshTokenEnabled() bool {
	return u.conf.GetRefreshTokenEnabled()
}

func (u *userusecase) refreshTokenRotationEnabled() bool {
	return u.conf.GetRefreshTokenRotationEnabled()
}

func (u *userusecase) getRefreshTokenExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetRefreshTokenExpiry()) * time.Second)
}

func (u *userusecase) getActivationLink() string {
	activationLink := u.conf.GetActivationLink()
	return activationLink
}

func (u *userusecase) getActivationLinkExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetActivationLinkExpiry()) * time.Second)

}

func (u *userusecase) getPasswordResetLinkExpiry() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetPasswordResetLinkExpiry()) * time.Second)

}
func (u *userusecase) getLoginAttemptSessionPeriod() time.Time {
	return time.Now().Add(time.Duration(u.conf.GetLoginAttemptSessionPeriod()*-1) * time.Second)

}

func (u *userusecase) getMaxLoginAttempt() int {
	return u.conf.GetMaxLoginAttempt()
}

func (u *userusecase) getPasswordResetLink() string {
	return u.conf.GetPasswordResetLink()
}
