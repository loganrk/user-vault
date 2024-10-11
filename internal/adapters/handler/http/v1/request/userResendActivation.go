package request

import (
	"encoding/json"
	"errors"
	"mayilon/internal/port"
	"net/http"
)

func NewUserResendActivation(r *http.Request) (port.UserResendActivationClientRequest, error) {
	var u userResendActivation
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return &u, err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
	}

	return &u, nil
}

func (u *userResendActivation) Validate() error {
	if !emailRegex.MatchString(u.Username) {

		return errors.New("invalid username")
	}
	return nil
}

func (u *userResendActivation) GetUsername() string {
	return u.Username
}
