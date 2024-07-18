package request

import (
	"encoding/json"
	"net/http"
	"unicode"
)

type userRegister struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func NewUserRegister() *userRegister {
	return &userRegister{}
}

func (u *userRegister) Parse(r *http.Request) error {
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(u)
		if err != nil {
			return err
		}
	} else {
		u.Username = r.URL.Query().Get("username")
		u.Password = r.URL.Query().Get("password")
		u.Name = r.URL.Query().Get("name")
	}

	return nil
}

func (u *userRegister) Validate() string {
	if !emailRegex.MatchString(u.Username) {

		return "invalid username"
	}

	if u.Password == "" {
		return "invalid password"
	}

	if u.Name == "" {
		return "invalid name"
	}

	if !passwordRegex.MatchString(u.Password) {

		return "password must be between 8 and 12 characters long"
	}

	if !hasDigit(u.Password) {

		return "password must contain at least one digit"
	}

	if !hasLowercase(u.Password) {

		return "password must contain at least one lowercase letter"
	}

	if !hasUppercase(u.Password) {

		return "password must contain at least one uppercase letter"
	}

	if !hasSpecialChar(u.Password) {

		return "password must contain at least one special character"
	}

	return ""
}

func isValidLength(s string) bool {
	length := len(s)
	return length >= 8 && length <= 12
}

func hasLowercase(s string) bool {
	for _, c := range s {
		if unicode.IsLower(c) {
			return true
		}
	}
	return false
}

func hasUppercase(s string) bool {
	for _, c := range s {
		if unicode.IsUpper(c) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, c := range s {
		if unicode.IsDigit(c) {
			return true
		}
	}
	return false
}

func hasSpecialChar(s string) bool {
	specialChars := "@$!%*?&"
	for _, c := range s {
		if containsRune(specialChars, c) {
			return true
		}
	}
	return false
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
