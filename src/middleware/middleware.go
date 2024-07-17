package middleware

import "net/http"

type Auth interface {
	Use() http.HandlerFunc
}
