package middleware

import "net/http"

type Authz interface {
	Use() http.HandlerFunc
}

type Authn interface {
	CreateToken(uid int) (string, error)
}
