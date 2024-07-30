package user

import (
	"encoding/json"
	"mayilon/pkg/http/v1/request"
	"mayilon/pkg/utils"
	"net/http"
)

type userRegister struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func NewUserRegister() *userRegister {
	return &userRegister{}
}

func (u *userRegister) Parse(r *http.Request) error {
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
		u.Password = r.URL.Query().Get("password")
		u.Name = r.URL.Query().Get("name")
	}

	return nil
}

func (u *userRegister) Validate() string {
	if !request.EmailRegex.MatchString(u.Username) {

		return "invalid username"
	}

	if u.Password == "" {
		return "invalid password"
	}

	if u.Name == "" {
		return "invalid name"
	}

	if !request.PasswordRegex.MatchString(u.Password) {

		return "password must be between 8 and 12 characters long"
	}

	if !utils.HasDigit(u.Password) {

		return "password must contain at least one digit"
	}

	if !utils.HasLowercase(u.Password) {

		return "password must contain at least one lowercase letter"
	}

	if !utils.HasUppercase(u.Password) {

		return "password must contain at least one uppercase letter"
	}

	if !utils.HasSpecialChar(u.Password) {

		return "password must contain at least one special character"
	}

	return ""
}
