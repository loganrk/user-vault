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
	CreateAccessToken(uid int, uname string, name string) (string, error)
	CreateRefreshToken(uid int) (string, error)
	CreateRefreshTokenWithCustomExpiry(uid int, expiry time.Time) (string, error)
	GetRefreshTokenExpiry(token string) (time.Time, error)
	GetRefreshTokenData(tokenStringEcr string) (int, time.Time, error)
}

func NewAuthz(authzToken string) Authz {
	return authz.New(authzToken)
}

func NewAuthn(cryptoKey string, accessTokenExpiry int, refreshTokenExpiry int, cipherIns cipher.Cipher) Authn {
	return authn.New(cryptoKey, accessTokenExpiry, refreshTokenExpiry, cipherIns)
}
