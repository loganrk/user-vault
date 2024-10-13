package request

import (
	"encoding/json"
	"errors"
	"mayilon/internal/port"
	"net/http"
)

func NewUserLogin(r *http.Request) (port.UserLoginClientRequest, error) {
	var u userLogin
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&u)
		if err != nil {
			return &u, err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
		u.Password = r.URL.Query().Get("password")
	}

	return &u, nil
}

func (u *userLogin) Validate() error {
	if !emailRegex.MatchString(u.Username) {

		return errors.New("invalid username")
	}

	if !passwordRegex.MatchString(u.Password) {

		return errors.New("invalid password")
	}

	return nil
}

func (u *userLogin) GetUsername() string {
	return u.Username
}

func (u *userLogin) GetPassword() string {
	return u.Password
}
