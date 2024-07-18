package authz

import (
	"mayilon/src/middleware"
	"net/http"
)

type authz struct {
	token string
}

func New(authzToken string) middleware.Authz {
	return &authz{
		token: "Bearer " + authzToken,
	}
}

func (a *authz) Use() http.HandlerFunc {
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

		w.Header().Set("Content-Type", "application/json")

	})
}
