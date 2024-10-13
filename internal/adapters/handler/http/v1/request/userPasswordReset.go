package request

import (
	"encoding/json"
	"errors"
	"mayilon/internal/port"
	"mayilon/internal/utils"
	"net/http"
)

func NewUserResetPassword(r *http.Request) (port.UserResetPasswordClientRequest, error) {
	var u userResetPassword
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&u)
		if err != nil {
			return &u, err
		}
	} else {
		u.Password = r.URL.Query().Get("password")
		u.Token = r.URL.Query().Get("token")
	}

	return &u, nil
}

func (u *userResetPassword) Validate() error {
	if u.Token == "" {

		return errors.New("invalid token")
	}

	if u.Password == "" {
		return errors.New("invalid password")
	}

	if !passwordRegex.MatchString(u.Password) {

		return errors.New("password must be between 8 and 12 characters long")
	}

	if !utils.HasDigit(u.Password) {

		return errors.New("password must contain at least one digit")
	}

	if !utils.HasLowercase(u.Password) {

		return errors.New("password must contain at least one lowercase letter")
	}

	if !utils.HasUppercase(u.Password) {

		return errors.New("password must contain at least one uppercase letter")
	}

	if !utils.HasSpecialChar(u.Password) {

		return errors.New("password must contain at least one special character")
	}

	return nil
}

func (u *userResetPassword) GetPassword() string {
	return u.Password

}

func (u *userResetPassword) GetToken() string {
	return u.Token
}
