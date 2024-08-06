package middleware

import (
	"mayilon/pkg/middleware/authn"
	"mayilon/pkg/middleware/authz"

	"github.com/loganrk/go-cipher"

	"net/http"
)

type Authz interface {
	Use() http.HandlerFunc
}

type Authn interface {
	CreateToken(uid int) (string, error)
}

func NewAuthz(authzToken string) Authz {
	return authz.New(authzToken)
}

func NewAuthn(cryptoKey string, tokenExpiry int, cipherIns cipher.Cipher) Authn {
	return authn.New(cryptoKey, tokenExpiry, cipherIns)
}
