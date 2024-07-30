package user

import (
	"encoding/json"
	"mayilon/pkg/http/v1/request"
	"net/http"
)

type userLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewUserLogin() *userLogin {
	return &userLogin{}
}

func (u *userLogin) Parse(r *http.Request) error {
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
		u.Password = r.URL.Query().Get("password")
	}

	return nil
}

func (u *userLogin) Validate() string {
	if !request.EmailRegex.MatchString(u.Username) {

		return "invalid username"
	}

	if !request.PasswordRegex.MatchString(u.Password) {

		return "invalid password"
	}

	return ""
}
