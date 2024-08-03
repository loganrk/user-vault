package gomail

import (
	"strconv"

	gomail "gopkg.in/gomail.v2"
)

type email struct {
	dialer *gomail.Dialer
}

func New(hostname, port, username, password string) *email {
	portInt, _ := strconv.Atoi(port)
	dialer := gomail.NewDialer(hostname, portInt, username, password)
	return &email{
		dialer: dialer,
	}
}
