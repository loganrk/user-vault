package user

import (
	"encoding/json"
	"errors"
	"net/http"
)

func NewUserActivation() *newUserActivation {
	return &newUserActivation{}
}

func (u *newUserActivation) Parse(r *http.Request) error {
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return err
		}
	} else {
		u.Token = r.URL.Query().Get("token")
	}

	return nil
}

func (u *newUserActivation) Validate() error {
	if u.Token == "" {

		return errors.New("invalid token")
	}

	return nil
}
