package user

import (
	"encoding/json"
	"errors"
	"net/http"
)

func NewUserLogout() *userLogout {
	return &userLogout{}
}

func (u *userLogout) Parse(r *http.Request) error {
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return err
		}
	} else {
		u.RefreshToken = r.URL.Query().Get("refresh_token")
	}

	return nil
}

func (u *userLogout) Validate() error {
	if u.RefreshToken == "" {
		return errors.New("invalid refresh token")
	}

	return nil
}
