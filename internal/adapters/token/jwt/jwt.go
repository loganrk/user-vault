package jwt

import (
	"crypto/rsa"
	"errors"
	"time"
	"userVault/internal/port"

	"github.com/golang-jwt/jwt/v5"
)

type token struct {
	method     string // "HS256" or "RS256"
	hmacKey    []byte
	rsaPrivKey *rsa.PrivateKey
	rsaPubKey  *rsa.PublicKey
}

func New(method string, hmacKey []byte, rsaPrivKey *rsa.PrivateKey, rsaPubKey *rsa.PublicKey) port.Token {
	return &token{
		method:     method,
		hmacKey:    hmacKey,
		rsaPrivKey: rsaPrivKey,
		rsaPubKey:  rsaPubKey,
	}
}

func (t *token) signToken(claims jwt.Claims) (string, error) {
	var signingMethod jwt.SigningMethod
	var signedToken string
	var err error

	switch t.method {
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.hmacKey)
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.rsaPrivKey)
	default:
		return "", errors.New("unsupported signing method")
	}

	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func (t *token) CreateAccessToken(uid int, uname, name string, expiry time.Time) (string, error) {
	claims := jwt.MapClaims{
		"type":  "access",
		"uid":   uid,
		"uname": uname,
		"name":  name,
		"exp":   expiry.Unix(),
	}
	return t.signToken(claims)
}

func (t *token) CreateRefreshToken(uid int, expiry time.Time) (string, error) {
	claims := jwt.MapClaims{
		"type": "refresh",
		"uid":  uid,
		"exp":  expiry.Unix(),
	}
	return t.signToken(claims)
}

func (t *token) parseTokenWithoutVerification(encryptedToken string) (jwt.MapClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(encryptedToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

func (t *token) GetAccessTokenData(encryptedToken string) (int, time.Time, error) {
	claims, err := t.parseTokenWithoutVerification(encryptedToken)
	if err != nil {
		return 0, time.Time{}, err
	}

	if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
		return 0, time.Time{}, errors.New("token type (`type`) not found or mismatch in token")
	}

	uid, ok := claims["uid"].(float64)
	if !ok {
		return 0, time.Time{}, errors.New("user id (`uid`) not found in token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, time.Time{}, errors.New("expiration time (`exp`) not found in token")
	}

	return int(uid), time.Unix(int64(exp), 0), nil
}

func (t *token) GetRefreshTokenData(encryptedToken string) (int, time.Time, error) {
	claims, err := t.parseTokenWithoutVerification(encryptedToken)
	if err != nil {
		return 0, time.Time{}, err
	}

	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		return 0, time.Time{}, errors.New("token type (`type`) not found or mismatch in token")
	}

	uid, ok := claims["uid"].(float64)
	if !ok {
		return 0, time.Time{}, errors.New("user id (`uid`) not found in token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, time.Time{}, errors.New("expiration time (`exp`) not found in token")
	}

	return int(uid), time.Unix(int64(exp), 0), nil
}
