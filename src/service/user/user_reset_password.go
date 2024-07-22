package user

import (
	"context"
	"mayilon/src/types"
	"mayilon/src/utils"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	USER_PASSWORD_RESET_TOKEN_ID_MACRO = "{{tokenId}}"
	USER_PASSWORD_RESET_TOKEN_MACRO    = "{{token}}"
	USER_PASSWORD_RESET_LINK_MACRO     = "{{link}}"
	USER_PASSWORD_RESET_NAME_MACRO     = "{{name}}"
	USER_PASSWORD_RESET_APP_NAME_MACRO = "{{appName}}"
)

func (u *userService) CreatePasswordResetToken(ctx context.Context, userid int) (int, string) {
	passwordResetToken := utils.GenerateRandomString(25)

	tokenId, err := u.store.GetPasswordResetTokenIdByToken(ctx, passwordResetToken)
	if err != nil {
		return 0, ""
	}

	if tokenId != 0 {
		return u.CreatePasswordResetToken(ctx, userid)
	}

	tokenData := types.UserPasswordReset{
		UserId:    userid,
		Token:     passwordResetToken,
		ExpiredAt: time.Now().Add(time.Duration(u.passwordResetLinkExpiry) * time.Second),
	}

	tokenId, err = u.store.CreatePasswordResetToken(ctx, tokenData)
	if err != nil {
		return 0, ""
	}
	return tokenId, passwordResetToken
}

func (u *userService) GetPasswordResetLink(tokenId int, token string) string {
	passwordResetLink := u.passwordResetLink
	return u.passwordResetLinkMacroReplacement(passwordResetLink, tokenId, token)

}

func (u *userService) passwordResetLinkMacroReplacement(passwordResetLink string, tokenId int, token string) string {
	s := strings.NewReplacer(
		USER_PASSWORD_RESET_TOKEN_ID_MACRO, strconv.Itoa(tokenId),
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

func (u *userService) GetPasswordResetDataByToken(ctx context.Context, token string) types.UserPasswordReset {
	tokenData, err := u.store.GetPasswordResetDataByToken(ctx, token)
	if err != nil {
		return types.UserPasswordReset{}
	}

	return tokenData

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
