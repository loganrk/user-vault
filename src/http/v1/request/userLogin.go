package request

import (
	"encoding/json"
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
	if !emailRegex.MatchString(u.Username) {

		return "invalid username"
	}

	if !passwordRegex.MatchString(u.Password) {

		return "invalid password"
	}

	return ""
}
