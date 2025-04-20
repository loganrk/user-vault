package email

import (
	"errors"
	"strings"
	"userVault/config"
	"userVault/internal/constant"
	"userVault/internal/port"
	"userVault/internal/utils"
)

type email struct {
	appName               string
	activationTemplate    string
	activationtLink       string
	passwordResetTemplate string
	passwordResetLink     string
}

func New(appName string, conf config.Email) (port.Emailer, error) {

	activationTemplate, err := utils.FindFileContent(conf.GetActivationEmailTemplatePath())
	if err != nil {
		return nil, err
	}
	passwordResetTemplate, err := utils.FindFileContent(conf.GetPasswordResetTemplatePath())
	if err != nil {
		return nil, err
	}

	return &email{
		appName:               appName,
		activationTemplate:    activationTemplate,
		activationtLink:       conf.GetActivationLink(),
		passwordResetTemplate: passwordResetTemplate,
		passwordResetLink:     conf.GetPasswordResetLink(),
	}, nil
}

func (u *email) PrepareActivationEmail(name, token string) (string, string, error) {
	activationLink := u.activationLinkMacroReplacement(u.activationtLink, token)
	if activationLink != "" {
		// Replace macros in the email template and send the activation email
		emailContent := u.activationTemplateMacroReplacement(u.activationTemplate, name, activationLink)
		if emailContent != "" {
			emailSubject := u.getActivationEmailSubject()
			return emailContent, emailSubject, nil
		}
		return "", "", errors.New("activation email content is empty")
	}

	return "", "", errors.New("activation email link is empty")
}

func (u *email) PreparePasswordResetEmail(name, token string) (string, string, error) {
	passwordResetLink := u.passwordResetLinkMacroReplacement(u.activationtLink, token)
	if passwordResetLink != "" {
		// Replace macros in the email template and send the activation email
		emailContent := u.passwordResetTemplateMacroReplacement(u.activationTemplate, name, passwordResetLink)
		if emailContent != "" {
			emailSubject := u.getPasswordResetEmailSubject()
			return emailContent, emailSubject, nil
		}
		return "", "", errors.New("password reset email content is empty")
	}

	return "", "", errors.New("password reset email link is empty")
}

// passwordResetLinkMacroReplacement replaces macros in the password reset link with the provided token.
func (e *email) passwordResetLinkMacroReplacement(passwordResetLink string, token string) string {
	s := strings.NewReplacer(
		constant.USER_PASSWORD_RESET_TOKEN_MACRO, token)

	return s.Replace(passwordResetLink)
}

// passwordResetTemplateMacroReplacement replaces macros in the email template with actual values.
func (e *email) passwordResetTemplateMacroReplacement(template string, name string, passwordResetLink string) string {
	s := strings.NewReplacer(
		constant.USER_PASSWORD_RESET_APP_NAME_MACRO, e.appName,
		constant.USER_PASSWORD_RESET_NAME_MACRO, name,
		constant.USER_PASSWORD_RESET_LINK_MACRO, passwordResetLink)

	return s.Replace(template)
}

// activationLinkMacroReplacement replaces macros in the activation link with the provided token data.
func (e *email) activationLinkMacroReplacement(activationLink string, token string) string {
	s := strings.NewReplacer(
		constant.USER_ACTIVATION_TOKEN_MACRO, token)

	return s.Replace(activationLink)
}

// activationTemplateMacroReplacement replaces macros in the activation email template with actual values.
func (e *email) activationTemplateMacroReplacement(template string, name string, activationLink string) string {
	s := strings.NewReplacer(
		constant.USER_ACTIVATION_APP_NAME_MACRO, e.appName,
		constant.USER_ACTIVATION_NAME_MACRO, name,
		constant.USER_ACTIVATION_LINK_MACRO, activationLink)

	return s.Replace(template)

}
func (e *email) getPasswordResetEmailSubject() string {
	s := strings.NewReplacer(
		constant.USER_ACTIVATION_APP_NAME_MACRO, e.appName,
	)

	return s.Replace(constant.USER_PASSWORD_RESET_EMAIL_SUBJECT)

}
func (e *email) getActivationEmailSubject() string {
	s := strings.NewReplacer(
		constant.USER_ACTIVATION_APP_NAME_MACRO, e.appName,
	)

	return s.Replace(constant.USER_ACTIVATION_EMAIL_SUBJECT)

}
