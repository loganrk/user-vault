package email

import (
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

func New(conf config.Email) (port.Email, error) {

	activationTemplate, err := utils.FindFileContent(conf.GetActivationEmailTemplatePath())
	if err != nil {
		return nil, err
	}
	passwordResetTemplate, err := utils.FindFileContent(conf.GetPasswordResetTemplatePath())
	if err != nil {
		return nil, err
	}

	return &email{
		activationTemplate:    activationTemplate,
		activationtLink:       conf.GetActivationLink(),
		passwordResetTemplate: passwordResetTemplate,
		passwordResetLink:     conf.GetPasswordResetLink(),
	}, nil
}

func (u *email) SendActivationEmail(toAddress, name, token string) error {
	activationLink := u.activationLinkMacroReplacement(u.activationtLink, token)
	if activationLink != "" {
		// Replace macros in the email template and send the activation email
		emailTemplate := u.activationTemplateMacroReplacement(u.activationTemplate, name, activationLink)
		if emailTemplate != "" {
			// send to kafka
		}
	}

	return nil
}

func (u *email) SendPasswordResetEmail(toAddress, name, token string) error {
	passwordResetLink := u.passwordResetLinkMacroReplacement(u.activationtLink, token)
	if passwordResetLink != "" {
		// Replace macros in the email template and send the activation email
		emailTemplate := u.passwordResetTemplateMacroReplacement(u.activationTemplate, name, passwordResetLink)
		if emailTemplate != "" {
			// send to kafka
		}
	}

	return nil
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
