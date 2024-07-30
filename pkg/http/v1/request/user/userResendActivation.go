package user

import (
	"encoding/json"
	"mayilon/pkg/http/v1/request"
	"net/http"
)

type userResendActivation struct {
	Username string `json:"username"`
}

func NewUserResendActivation() *userResendActivation {
	return &userResendActivation{}
}

func (u *userResendActivation) Parse(r *http.Request) error {
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

func (u *userResendActivation) Validate() string {
	if !request.EmailRegex.MatchString(u.Username) {

		return "invalid username"
	}
	return ""
}
