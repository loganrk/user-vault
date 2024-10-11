package jwt

import (
	"errors"
	"fmt"
	"mayilon/internal/port"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type token struct {
	cryptoKey          string
	accessTokenExpiry  int
	refreshTokenExpiry int
	cipher             port.Cipher
}

func New(cryptoKey string, accessTokenExpiry int, refreshTokenExpiry int, cipherIns port.Cipher) port.Token {
	return &token{
		cryptoKey:          cryptoKey,
		accessTokenExpiry:  accessTokenExpiry,
		refreshTokenExpiry: refreshTokenExpiry,
		cipher:             cipherIns,
	}
}

func (t *token) CreateAccessToken(uid int, uname string, name string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"type":  "access",
			"uid":   uid,
			"uname": uname,
			"name":  name,
			"exp":   time.Now().Add(time.Second * time.Duration(t.accessTokenExpiry)).Unix(),
		})

	tokenString, err := token.SignedString([]byte(t.cipher.GetKey()))
	if err != nil {
		return "", err
	}

	tokenStringEcr, err := t.cipher.Encrypt(tokenString)
	if err != nil {
		return "", err
	}

	return tokenStringEcr, nil
}

func (t *token) CreateRefreshToken(uid int) (string, error) {

	return t.createRefreshToken(uid, time.Now().Add(time.Second*time.Duration(t.refreshTokenExpiry)))
}

func (t *token) CreateRefreshTokenWithCustomExpiry(uid int, expiry time.Time) (string, error) {
	return t.createRefreshToken(uid, expiry)
}

func (t *token) createRefreshToken(uid int, expiry time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"type": "refresh",
			"uid":  uid,
			"exp":  expiry.Unix(),
		})

	tokenString, err := token.SignedString([]byte(t.cipher.GetKey()))
	if err != nil {
		return "", err
	}

	tokenStringEcr, err := t.cipher.Encrypt(tokenString)
	if err != nil {
		return "", err
	}

	return tokenStringEcr, nil
}

func (t *token) GetRefreshTokenData(tokenStringEcr string) (int, time.Time, error) {
	tokenString, err := t.cipher.Decrypt(tokenStringEcr)
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

		if uid, ok := claims["uid"].(float64); ok {
			if exp, ok := claims["exp"].(float64); ok {
				expirationTime := time.Unix(int64(exp), 0)
				return int(uid), expirationTime, nil
			}
			return 0, time.Time{}, errors.New("expiration time (`exp`) not found in token")
		}
		return 0, time.Time{}, errors.New("user id (`uid`) not found in token")
	}
	return 0, time.Time{}, errors.New("invalid token claims")
}

func (t *token) GetRefreshTokenExpiry(tokenStringEcr string) (time.Time, error) {
	tokenString, err := t.cipher.Decrypt(tokenStringEcr)
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

func (t *token) GetAccessTokenData(encryptedToken string) (int, time.Time, error) {
	tokenString, err := t.cipher.Decrypt(encryptedToken)
	if err != nil {
		return 0, time.Time{}, err
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return 0, time.Time{}, err

	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {

		if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
			return 0, time.Time{}, errors.New("token type (`type`) not found or mismatch in token")
		}
		for key, value := range claims {
			fmt.Printf("Key: %s, Type: %s, Value: %v\n", key, reflect.TypeOf(value), value)
		}
		if uid, ok := claims["uid"].(float64); ok {
			if exp, ok := claims["exp"].(float64); ok {
				expirationTime := time.Unix(int64(exp), 0)
				return int(uid), expirationTime, nil
			}
			return 0, time.Time{}, errors.New("expiration time (`exp`) not found in token")
		}
		return 0, time.Time{}, errors.New("user id (`uid`) not found in token")
	}
	return 0, time.Time{}, errors.New("invalid token claims")
}
