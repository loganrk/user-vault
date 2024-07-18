package authn

import (
	"fmt"
	"mayilon/src/middleware"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type authn struct {
	secretKey   string
	tokenExpiry int
}

func New(secretKey string, tokenExpiry int) middleware.Authn {
	return &authn{
		secretKey:   secretKey,
		tokenExpiry: tokenExpiry,
	}
}

func (a *authn) CreateToken(uid int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": uid,
			"exp":      time.Now().Add(time.Second * time.Duration(a.tokenExpiry)).Unix(),
		})

	tokenString, err := token.SignedString([]byte(a.secretKey))
	fmt.Println(err)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
