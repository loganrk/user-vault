package email

import (
	"mayilon/src/lib/email/gomail"
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
}
