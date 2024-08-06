package authn

import (
	"time"

	cipher "github.com/loganrk/go-cipher"

	"github.com/golang-jwt/jwt/v5"
)

type authn struct {
	cipher      cipher.Cipher
	cryptoKey   string
	tokenExpiry int
}

func New(cryptoKey string, tokenExpiry int, cipherIns cipher.Cipher) *authn {
	return &authn{
		cipher:      cipherIns,
		cryptoKey:   cryptoKey,
		tokenExpiry: tokenExpiry,
	}
}

func (a *authn) CreateToken(uid int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": uid,
			"exp":      time.Now().Add(time.Second * time.Duration(a.tokenExpiry)).Unix(),
		})

	tokenString, err := token.SignedString([]byte(a.cryptoKey))
	if err != nil {
		return "", err
	}

	tokenStringEcr, err := a.cipher.Encrypt(tokenString)
	if err != nil {
		return "", err
	}

	return tokenStringEcr, nil
}
