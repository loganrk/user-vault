package request

import (
	"encoding/json"
	"errors"
	"mayilon/internal/port"
	"net/http"
)

func NewUserLogout(r *http.Request) (port.UserLogoutClientRequest, error) {
	var u userLogout
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return &u, err
		}
	} else {
		u.RefreshToken = r.URL.Query().Get("refresh_token")
	}
	return &u, nil
}

func (u *userLogout) Validate() error {
	if u.RefreshToken == "" {
		return errors.New("invalid refresh token")
	}

	return nil
}

func (u *userLogout) GetRefreshToken() string {
	return u.RefreshToken
}
