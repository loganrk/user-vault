package user

import (
	"encoding/json"
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

func (u *userLogout) Validate() string {
	if u.RefreshToken == "" {
		return "invalid refresh token"
	}

	return ""
}
