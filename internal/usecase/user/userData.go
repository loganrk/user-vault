package user

import (
	"context"
	"mayilon/internal/constant"
	"mayilon/internal/domain"
	"mayilon/internal/utils"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (u *userusecase) createActivationToken(ctx context.Context, userid int) (int, string, error) {
	activationToken := utils.GenerateRandomString(25)

	tokenData, err := u.getActivationByToken(ctx, activationToken)
	if err != nil {
		return 0, "", err
	}

	if tokenData.Id != 0 {
		return u.createActivationToken(ctx, userid)
	}

	tokenData = domain.UserActivationToken{
		UserId:    userid,
		Token:     activationToken,
		Status:    constant.USER_ACTIVATION_TOKEN_STATUS_ACTIVE,
		ExpiresAt: u.getActivationLinkExpiry(),
	}

	tokenId, err := u.createActivation(ctx, tokenData)
	if err != nil {
		return 0, "", err
	}
	return tokenId, activationToken, nil
}

func (u *userusecase) storeRefreshToken(ctx context.Context, userid int, token string, expiresAt time.Time) (int, error) {

	refreshTokenData := domain.UserRefreshToken{
		UserId:    userid,
		Token:     token,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	refreshTokenId, err := u.createRefreshToken(ctx, refreshTokenData)
	if err != nil {
		return 0, err
	}
	return refreshTokenId, nil
}

func (u *userusecase) createPasswordResetToken(ctx context.Context, userid int) (int, string, error) {
	passwordResetData, err := u.getActivePasswordResetByUserId(ctx, userid)
	if err != nil {
		return 0, "", err
	}

	if passwordResetData.Id != 0 && passwordResetData.Token != "" {
		return passwordResetData.Id, passwordResetData.Token, nil
	}

	passwordResetToken := utils.GenerateRandomString(25)

	alreadyExiststData, err := u.getPasswordResetByToken(ctx, passwordResetToken)
	if err != nil {
		return 0, "", err
	}

	if alreadyExiststData.Id != 0 {
		return u.createPasswordResetToken(ctx, userid)
	}

	passwordResetData = domain.UserPasswordReset{
		UserId:    userid,
		Token:     passwordResetToken,
		Status:    constant.USER_PASSWORD_RESET_STATUS_ACTIVE,
		ExpiresAt: u.getPasswordResetLinkExpiry(),
	}

	passwordResetId, err := u.mysql.CreatePasswordReset(ctx, passwordResetData)
	if err != nil {
		return 0, "", err
	}
	return passwordResetId, passwordResetToken, nil
}

func (u *userusecase) checkLoginFailedAttempt(ctx context.Context, userId int) (int, error) {
	// TODO: add client based token
	attempCount, err := u.getUserLoginFailedAttemptCount(ctx, userId, u.getLoginAttemptSessionPeriod())
	if err != nil {

		return constant.LOGIN_ATTEMPT_FAILED, err
	}

	if attempCount >= u.getMaxLoginAttempt() {

		return constant.LOGIN_ATTEMPT_MAX_REACHED, nil
	}

	return constant.LOGIN_ATTEMPT_SUCCESS, nil
}

func (u *userusecase) checkPassword(ctx context.Context, password string, passwordHash string, saltHash string) (bool, error) {

	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password+saltHash))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (u *userusecase) newSaltHash() (string, error) {
	// Generate a random salt (using bcrypt's salt generation function)
	saltRaw := utils.GenerateRandomString(10)

	salt, err := bcrypt.GenerateFromPassword([]byte(saltRaw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(salt), nil
}

func (u *userusecase) passwordResetLinkMacroReplacement(passwordResetLink string, token string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_TOKEN_MACRO, token)

	return s.Replace(passwordResetLink)

}

func (u *userusecase) passwordResetTemplateMacroReplacement(template string, name string, passwordResetLink string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_APP_NAME_MACRO, u.appName,
		USER_PASSWORD_RESET_NAME_MACRO, name,
		USER_PASSWORD_RESET_LINK_MACRO, passwordResetLink)

	return s.Replace(template)
}

func (u *userusecase) sendPasswordReset(ctx context.Context, email string, template string) error {
	return nil
}

func (u *userusecase) activationLinkMacroReplacement(activationLink string, tokenId int, token string) string {
	s := strings.NewReplacer(
		USER_ACTIVATION_TOKEN_ID_MACRO, strconv.Itoa(tokenId),
		USER_ACTIVATION_TOKEN_MACRO, token)

	return s.Replace(activationLink)

}

func (u *userusecase) activationTemplateMacroReplacement(template string, name string, activationLink string) string {
	s := strings.NewReplacer(
		USER_ACTIVATION_APP_NAME_MACRO, u.appName,
		USER_ACTIVATION_NAME_MACRO, name,
		USER_ACTIVATION_LINK_MACRO, activationLink)

	return s.Replace(template)

}

func (u *userusecase) sendActivation(ctx context.Context, email string, template string) error {

	return nil
}
