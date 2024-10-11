package user

import (
	"context"
	"mayilon/internal/constant"
	"mayilon/internal/domain"
	"mayilon/internal/utils"
	"strconv"
	"strings"
	"time"
)

const (
	USER_ACTIVATION_TOKEN_ID_MACRO = "{{tokenId}}"
	USER_ACTIVATION_TOKEN_MACRO    = "{{token}}"
	USER_ACTIVATION_LINK_MACRO     = "{{link}}"
	USER_ACTIVATION_NAME_MACRO     = "{{name}}"
	USER_ACTIVATION_APP_NAME_MACRO = "{{appName}}"
)

func (u *userusecase) CreateActivationToken(ctx context.Context, userid int) (int, string, error) {
	activationToken := utils.GenerateRandomString(25)

	tokenData, err := u.mysql.GetActivationByToken(ctx, activationToken)
	if err != nil {
		return 0, "", err
	}

	if tokenData.Id != 0 {
		return u.CreateActivationToken(ctx, userid)
	}

	tokenData = domain.UserActivationToken{
		UserId:    userid,
		Token:     activationToken,
		Status:    constant.USER_ACTIVATION_TOKEN_STATUS_ACTIVE,
		ExpiresAt: time.Now().Add(time.Duration(u.conf.GetActivationLinkExpiry()) * time.Second),
	}

	tokenId, err := u.mysql.CreateActivation(ctx, tokenData)
	if err != nil {
		return 0, "", err
	}
	return tokenId, activationToken, nil
}

func (u *userusecase) GetActivationLink(tokenId int, token string) string {
	activationLink := u.conf.GetActivationLink()
	return u.activationLinkMacroReplacement(activationLink, tokenId, token)

}

func (u *userusecase) activationLinkMacroReplacement(activationLink string, tokenId int, token string) string {
	s := strings.NewReplacer(
		USER_ACTIVATION_TOKEN_ID_MACRO, strconv.Itoa(tokenId),
		USER_ACTIVATION_TOKEN_MACRO, token)

	return s.Replace(activationLink)

}

func (u *userusecase) GetActivationEmailTemplate(ctx context.Context, name string, activationLink string) (string, error) {
	templatePath := u.conf.GetActivationEmailTemplate()
	template, err := utils.FindFileContent(templatePath)
	if err != nil {
		return "", err
	}
	return u.activationTemplateMacroReplacement(template, name, activationLink), nil
}

func (u *userusecase) activationTemplateMacroReplacement(template string, name string, activationLink string) string {
	s := strings.NewReplacer(
		USER_ACTIVATION_APP_NAME_MACRO, u.appName,
		USER_ACTIVATION_NAME_MACRO, name,
		USER_ACTIVATION_LINK_MACRO, activationLink)

	return s.Replace(template)

}

func (u *userusecase) SendActivation(ctx context.Context, email string, template string) error {

	return nil
}

func (u *userusecase) GetUserActivationByToken(ctx context.Context, token string) (domain.UserActivationToken, error) {
	tokenData, err := u.mysql.GetActivationByToken(ctx, token)
	return tokenData, err
}

func (u *userusecase) UpdatedActivationtatus(ctx context.Context, id int, status int) error {
	err := u.mysql.UpdatedActivationtatus(ctx, id, status)

	return err
}

func (u *userusecase) UpdateStatus(ctx context.Context, userid int, status int) error {

	err := u.mysql.UpdateStatus(ctx, userid, status)
	return err

}
