package request

import (
	"encoding/json"
	"net/http"
)

type userForgotPassword struct {
	Username string `json:"username"`
}

func NewUserForgotPassword() *userForgotPassword {
	return &userForgotPassword{}
}

func (u *userForgotPassword) Parse(r *http.Request) error {
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
	}

	return nil
}

func (u *userForgotPassword) Validate() string {
	if !emailRegex.MatchString(u.Username) {

		return "invalid username"
	}
	return ""
}
