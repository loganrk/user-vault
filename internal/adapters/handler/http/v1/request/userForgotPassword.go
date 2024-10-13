package request

import (
	"encoding/json"
	"errors"
	"mayilon/internal/port"
	"net/http"
)

func NewUserForgotPassword(r *http.Request) (port.UserForgotPasswordClientRequest, error) {
	var u userForgotPassword
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&u)
		if err != nil {
			return &u, err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
	}

	return &u, nil
}

func (u *userForgotPassword) Validate() error {
	if !emailRegex.MatchString(u.Username) {

		return errors.New("invalid username")
	}
	return nil
}

func (u *userForgotPassword) GetUsername() string {
	return u.Username

}
