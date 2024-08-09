package middleware

import (
	"mayilon/pkg/middleware/authn"
	"mayilon/pkg/middleware/authz"
	"time"

	"github.com/loganrk/go-cipher"

	"net/http"
)

type Authz interface {
	Use() http.HandlerFunc
}

type Authn interface {
	CreateAccessToken(uid int) (string, error)
	CreateRefreshToken(uid int) (string, error)
	GetRefreshTokenExpiry(token string) (time.Time, error)
	GetRefreshToken(tokenStringEcr string) (int, time.Time, error)
}

func NewAuthz(authzToken string) Authz {
	return authz.New(authzToken)
}

func NewAuthn(cryptoKey string, accessTokenExpiry int, refreshTokenExpiry int, cipherIns cipher.Cipher) Authn {
	return authn.New(cryptoKey, accessTokenExpiry, refreshTokenExpiry, cipherIns)
}
