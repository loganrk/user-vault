package request

import (
	"regexp"
)

var EmailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
var PasswordRegex = regexp.MustCompile(`^.{8,12}$`)
