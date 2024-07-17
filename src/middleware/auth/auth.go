package auth

import (
	"mayilon/src/middleware"
	"net/http"
)

type auth struct {
	token string
}

func New(authToken string) middleware.Auth {
	return &auth{
		token: "Bearer " + authToken,
	}
}

func (a *auth) Use() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "authorization header required", http.StatusUnauthorized)
			return
		}

		if token != a.token {
			http.Error(w, "invalid authorization token", http.StatusUnauthorized)
			return
		}

	})
}
