package authn

import (
	"errors"
	"time"

	cipher "github.com/loganrk/go-cipher"

	"github.com/golang-jwt/jwt/v5"
)

type authn struct {
	cipher             cipher.Cipher
	cryptoKey          string
	accessTokenExpiry  int
	refreshTokenExpiry int
}

func New(cryptoKey string, accessTokenExpiry int, refreshTokenExpiry int, cipherIns cipher.Cipher) *authn {
	return &authn{
		cipher:             cipherIns,
		cryptoKey:          cryptoKey,
		accessTokenExpiry:  accessTokenExpiry,
		refreshTokenExpiry: refreshTokenExpiry,
	}
}

func (a *authn) CreateAccessToken(uid int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"type": "access",
			"uid":  uid,
			"exp":  time.Now().Add(time.Second * time.Duration(a.accessTokenExpiry)).Unix(),
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

func (a *authn) CreateRefreshToken(uid int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"type": "refresh",
			"uid":  uid,
			"exp":  time.Now().Add(time.Second * time.Duration(a.refreshTokenExpiry)).Unix(),
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

func (a *authn) GetRefreshToken(tokenStringEcr string) (int, time.Time, error) {
	tokenString, err := a.cipher.Decrypt(tokenStringEcr)
	if err != nil {
		return 0, time.Time{}, err
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return 0, time.Time{}, err

	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
			return 0, time.Time{}, errors.New("token type (`type`) not found or mismatch in token")
		}

		if uid, ok := claims["uid"].(int); ok {
			if exp, ok := claims["exp"].(float64); ok {
				expirationTime := time.Unix(int64(exp), 0)
				return uid, expirationTime, nil
			}
			return 0, time.Time{}, errors.New("expiration time (`exp`) not found in token")
		}
		return 0, time.Time{}, errors.New("user id (`uid`) not found in token")
	}
	return 0, time.Time{}, errors.New("invalid token claims")
}

func (a *authn) GetRefreshTokenExpiry(tokenStringEcr string) (time.Time, error) {
	tokenString, err := a.cipher.Decrypt(tokenStringEcr)
	if err != nil {
		return time.Time{}, err
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, err

	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
			return time.Time{}, errors.New("token type (`type`) not found or mismatch in token")
		}
		if exp, ok := claims["exp"].(float64); ok {
			expirationTime := time.Unix(int64(exp), 0)
			return expirationTime, nil
		}
		return time.Time{}, errors.New("expiration time (`exp`) not found in token")
	}
	return time.Time{}, errors.New("invalid token claims")
}
