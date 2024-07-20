package gomail

import (
	gomail "gopkg.in/gomail.v2"
)

type email struct {
	dialer *gomail.Dialer
}

func New(hostname, port, username, password string) *email {
	dialer := gomail.NewDialer(hostname, port, username, password)
	return &email{
		dialer: dialer,
	}
}
