package authn

import (
	"mayilon/pkg/lib/chipper"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type authn struct {
	chipper     chipper.Chipper
	cryptoKey   string
	tokenExpiry int
}

func New(cryptoKey string, tokenExpiry int, chipperIns chipper.Chipper) *authn {
	return &authn{
		chipper:     chipperIns,
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

	tokenStringEcr, err := a.chipper.Encrypt(tokenString)
	if err != nil {
		return "", err
	}

	return tokenStringEcr, nil
}
