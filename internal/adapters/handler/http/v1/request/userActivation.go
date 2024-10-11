package request

import (
	"encoding/json"
	"errors"
	"mayilon/internal/port"
	"net/http"
)

func NewUserActivation(r *http.Request) (port.UserActivationClientRequest, error) {
	var u newUserActivation
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return &u, err
		}
	} else {
		u.Token = r.URL.Query().Get("token")
	}

	return &u, nil
}

func (u *newUserActivation) Validate() error {
	if u.Token == "" {

		return errors.New("invalid token")
	}

	return nil
}

func (u *newUserActivation) GetToken() string {
	return u.Token
}
