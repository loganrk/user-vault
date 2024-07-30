package user

import (
	"context"
	"mayilon/pkg/types"
	"mayilon/pkg/utils"
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

func (u *userService) CreatePasswordResetToken(ctx context.Context, userid int) (int, string) {
	passwordResetData, err := u.store.GetActivePasswordResetByUserId(ctx, userid)
	if err != nil {
		return 0, ""
	}

	if passwordResetData.Id != 0 && passwordResetData.Token != "" {
		return passwordResetData.Id, passwordResetData.Token
	}

	passwordResetToken := utils.GenerateRandomString(25)

	alreadyExiststData, err := u.store.GetPasswordResetByToken(ctx, passwordResetToken)
	if err != nil {
		return 0, ""
	}

	if alreadyExiststData.Id != 0 {
		return u.CreatePasswordResetToken(ctx, userid)
	}

	passwordResetData = types.UserPasswordReset{
		UserId:    userid,
		Token:     passwordResetToken,
		Status:    types.USER_PASSWORD_RESET_STATUS_ACTIVE,
		ExpiredAt: time.Now().Add(time.Duration(u.passwordResetLinkExpiry) * time.Second),
	}

	passwordResetId, err := u.store.CreatePasswordReset(ctx, passwordResetData)
	if err != nil {
		return 0, ""
	}
	return passwordResetId, passwordResetToken
}

func (u *userService) GetPasswordResetLink(token string) string {
	passwordResetLink := u.passwordResetLink

	return u.passwordResetLinkMacroReplacement(passwordResetLink, token)

}

func (u *userService) passwordResetLinkMacroReplacement(passwordResetLink string, token string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_TOKEN_MACRO, token)

	return s.Replace(passwordResetLink)

}

func (u *userService) GetPasswordResetEmailTemplate(ctx context.Context, name string, passwordResetLink string) string {
	templatePath := u.conf.passwordResetTemplatePath
	template, err := utils.FindFileContent(templatePath)
	if err != nil {
		return ""
	}
	return u.passwordResetTemplateMacroReplacement(template, name, passwordResetLink)
}

func (u *userService) passwordResetTemplateMacroReplacement(template string, name string, passwordResetLink string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_APP_NAME_MACRO, u.conf.appName,
		USER_PASSWORD_RESET_NAME_MACRO, name,
		USER_PASSWORD_RESET_LINK_MACRO, passwordResetLink)

	return s.Replace(template)
}

func (u *userService) SendPasswordReset(ctx context.Context, email string, template string) int {
	return types.EMAIL_STATUS_FAILED
}

func (u *userService) GetPasswordResetByToken(ctx context.Context, token string) types.UserPasswordReset {
	tokenData, err := u.store.GetPasswordResetByToken(ctx, token)
	if err != nil {
		return types.UserPasswordReset{}
	}

	return tokenData

}

func (u *userService) UpdatedPasswordResetStatus(ctx context.Context, id int, status int) {
	err := u.store.UpdatedPasswordResetStatus(ctx, id, status)
	if err != nil {

	}
}

func (u *userService) UpdatePassword(ctx context.Context, userid int, password string, saltHash string) bool {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(password+saltHash), u.passwordHashCost)
	if err != nil {
		return false
	}
	err = u.store.UpdatePassword(ctx, userid, string(hashPassword))
	if err != nil {
		return false
	}

	return true
}
