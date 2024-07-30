package user

import (
	"encoding/json"
	"net/http"
)

type newUserActivation struct {
	Token string `json:"token"`
}

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

func (u *newUserActivation) Validate() string {
	if u.Token == "" {

		return "invalid token"
	}

	return ""
}
