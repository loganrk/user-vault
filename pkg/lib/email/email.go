package email

import (
	"errors"
	"mayilon/pkg/lib/email/gomail"
)

const (
	LIB_GOMAIL = 1
)

type config struct {
	Type     int
	Hostname string
	Port     string
	Username string
	Password string
}

type Emailer interface {
}

func New(conf config) (Emailer, error) {

	switch conf.Type {

	case LIB_GOMAIL:
		gomail.New(conf.Hostname, conf.Port, conf.Username, conf.Password)

	default:
		gomail.New(conf.Hostname, conf.Port, conf.Username, conf.Password)

	}

	return nil, errors.New("type is not avilable")
}
