package request

import (
	"encoding/json"
	"errors"
	"mayilon/internal/port"
	"mayilon/internal/utils"
	"net/http"
)

func NewUserRegister(r *http.Request) (port.UserRegisterClientRequest, error) {
	var u userRegister
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&u)
		if err != nil {
			return &u, err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
		u.Password = r.URL.Query().Get("password")
		u.Name = r.URL.Query().Get("name")
	}

	return &u, nil
}

func (u *userRegister) Validate() error {
	if !emailRegex.MatchString(u.Username) {

		return errors.New("invalid username")
	}

	if u.Password == "" {
		return errors.New("invalid password")
	}

	if u.Name == "" {
		return errors.New("invalid name")
	}

	if !passwordRegex.MatchString(u.Password) {

		return errors.New("password must be between 8 and 12 characters long")
	}

	if !utils.HasDigit(u.Password) {

		return errors.New("password must contain at least one digit")
	}

	if !utils.HasLowercase(u.Password) {

		return errors.New("password must contain at least one lowercase letter")
	}

	if !utils.HasUppercase(u.Password) {

		return errors.New("password must contain at least one uppercase letter")
	}

	if !utils.HasSpecialChar(u.Password) {

		return errors.New("password must contain at least one special character")
	}

	return nil
}

func (u *userRegister) GetUsername() string {
	return u.Username
}

func (u *userRegister) GetPassword() string {
	return u.Password
}

func (u *userRegister) GetName() string {
	return u.Name
}
