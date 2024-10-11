package user

import (
	"context"
	"mayilon/internal/constant"
	"mayilon/internal/domain"
	"mayilon/internal/utils"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	USER_PASSWORD_RESET_TOKEN_MACRO    = "{{token}}"
	USER_PASSWORD_RESET_LINK_MACRO     = "{{link}}"
	USER_PASSWORD_RESET_NAME_MACRO     = "{{name}}"
	USER_PASSWORD_RESET_APP_NAME_MACRO = "{{appName}}"
)

func (u *userusecase) CreatePasswordResetToken(ctx context.Context, userid int) (int, string, error) {
	passwordResetData, err := u.mysql.GetActivePasswordResetByUserId(ctx, userid)
	if err != nil {
		return 0, "", err
	}

	if passwordResetData.Id != 0 && passwordResetData.Token != "" {
		return passwordResetData.Id, passwordResetData.Token, nil
	}

	passwordResetToken := utils.GenerateRandomString(25)

	alreadyExiststData, err := u.mysql.GetPasswordResetByToken(ctx, passwordResetToken)
	if err != nil {
		return 0, "", err
	}

	if alreadyExiststData.Id != 0 {
		return u.CreatePasswordResetToken(ctx, userid)
	}

	passwordResetData = domain.UserPasswordReset{
		UserId:    userid,
		Token:     passwordResetToken,
		Status:    constant.USER_PASSWORD_RESET_STATUS_ACTIVE,
		ExpiresAt: time.Now().Add(time.Duration(u.conf.GetPasswordResetLinkExpiry()) * time.Second),
	}

	passwordResetId, err := u.mysql.CreatePasswordReset(ctx, passwordResetData)
	if err != nil {
		return 0, "", err
	}
	return passwordResetId, passwordResetToken, nil
}

func (u *userusecase) GetPasswordResetLink(token string) string {
	passwordResetLink := u.conf.GetPasswordResetLink()

	return u.passwordResetLinkMacroReplacement(passwordResetLink, token)

}

func (u *userusecase) passwordResetLinkMacroReplacement(passwordResetLink string, token string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_TOKEN_MACRO, token)

	return s.Replace(passwordResetLink)

}

func (u *userusecase) GetPasswordResetEmailTemplate(ctx context.Context, name string, passwordResetLink string) (string, error) {
	templatePath := u.conf.GetPasswordResetTemplate()
	template, err := utils.FindFileContent(templatePath)
	if err != nil {
		return "", err
	}
	return u.passwordResetTemplateMacroReplacement(template, name, passwordResetLink), nil
}

func (u *userusecase) passwordResetTemplateMacroReplacement(template string, name string, passwordResetLink string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_APP_NAME_MACRO, u.appName,
		USER_PASSWORD_RESET_NAME_MACRO, name,
		USER_PASSWORD_RESET_LINK_MACRO, passwordResetLink)

	return s.Replace(template)
}

func (u *userusecase) SendPasswordReset(ctx context.Context, email string, template string) error {
	return nil
}

func (u *userusecase) GetPasswordResetByToken(ctx context.Context, token string) (domain.UserPasswordReset, error) {
	tokenData, err := u.mysql.GetPasswordResetByToken(ctx, token)

	return tokenData, err

}

func (u *userusecase) UpdatedPasswordResetStatus(ctx context.Context, id int, status int) error {
	err := u.mysql.UpdatedPasswordResetStatus(ctx, id, status)

	return err
}

func (u *userusecase) UpdatePassword(ctx context.Context, userid int, password string, saltHash string) error {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+saltHash), u.conf.GetPasswordHashCost())
	if err != nil {
		return err
	}
	err = u.mysql.UpdatePassword(ctx, userid, string(hashPassword))
	if err != nil {
		return err
	}

	return nil
}
