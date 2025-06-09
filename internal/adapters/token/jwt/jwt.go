package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/loganrk/user-vault/internal/utils"

	"github.com/golang-jwt/jwt/v5"
)

// token struct holds the necessary components for token creation and verification
// It includes the signing method (HS256 or RS256), the HMAC key for HS256, and the RSA keys for RS256
type token struct {
	method     string          // The signing method, can be either "HS256" or "RS256"
	hmacKey    []byte          // HMAC key used for HS256 signing
	rsaPrivKey *rsa.PrivateKey // Private RSA key used for RS256 signing
	rsaPubKey  *rsa.PublicKey  // Public RSA key used for RS256 verification
}

// New function initializes and returns a new instance of token with the provided parameters
func New(method string, hmacKey []byte, privateKeyPath, publicKeyPath string) (*token, error) {
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var err error
	switch method {
	case "HMAC", "HS256", "HS384", "HS512":
		if string(hmacKey) == "" {
			return nil, fmt.Errorf("HMAC key is missing for JWT method %s", method)
		}
	case "RSA", "RS256", "RS384", "RS512":
		privateKey, err = utils.LoadRSAPrivKeyFromFile(privateKeyPath)
		if err != nil {
			return nil, err
		}
		publicKey, err = utils.LoadRSAPubKeyFromFile(publicKeyPath)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported signing method: " + method)
	}

	return &token{
		method:     method,
		hmacKey:    hmacKey,
		rsaPrivKey: privateKey,
		rsaPubKey:  publicKey,
	}, nil
}

// signToken signs the provided claims using the appropriate signing method (HS256 or RS256)
// It returns the signed token as a string or an error if signing fails
func (t *token) signToken(claims jwt.Claims) (string, error) {
	var signingMethod jwt.SigningMethod
	var signedToken string
	var err error

	// Select the signing method based on the configured method
	switch t.method {
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.hmacKey)
	case "HS384":
		signingMethod = jwt.SigningMethodHS384
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.hmacKey)
	case "HS512":
		signingMethod = jwt.SigningMethodHS512
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.hmacKey)

	case "RS256":
		signingMethod = jwt.SigningMethodRS256
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.rsaPrivKey)
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.rsaPrivKey)
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
		signedToken, err = jwt.NewWithClaims(signingMethod, claims).SignedString(t.rsaPrivKey)

	default:
		return "", errors.New("unsupported signing method: " + t.method)
	}

	// Return the signed token or an error if the signing process failed
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// CreateAccessToken generates an access token with the user's ID, username, name, and expiration time
// It returns the signed access token as a string or an error if the signing process fails
func (t *token) CreateAccessToken(uid int, uname, name string, expiry time.Time) (string, error) {
	claims := jwt.MapClaims{
		"type":  "access",      // Token type, set as "access" for access tokens
		"uid":   uid,           // User ID
		"uname": uname,         // Username
		"name":  name,          // User's full name
		"exp":   expiry.Unix(), // Expiration time of the token in Unix format
	}
	return t.signToken(claims) // Sign and return the token
}

// CreateRefreshToken generates a refresh token with the user's ID and expiration time
// It returns the signed refresh token as a string or an error if the signing process fails
func (t *token) CreateRefreshToken(uid int, expiry time.Time) (string, error) {
	claims := jwt.MapClaims{
		"type": "refresh",     // Token type, set as "refresh" for refresh tokens
		"uid":  uid,           // User ID
		"exp":  expiry.Unix(), // Expiration time of the token in Unix format
	}
	return t.signToken(claims) // Sign and return the token
}

// parseTokenWithVerification parses and verifies the token using the appropriate key (hmacKey or rsaPubKey)
// It returns the claims if the token is valid, or an error if verification fails
func (t *token) parseTokenWithVerification(encryptedToken string) (jwt.MapClaims, error) {
	var key interface{}
	var signingMethod jwt.SigningMethod

	// Select the appropriate key and signing method based on the configured method
	switch t.method {
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
		key = t.hmacKey
	case "HS384":
		signingMethod = jwt.SigningMethodHS384
		key = t.hmacKey
	case "HS512":
		signingMethod = jwt.SigningMethodHS512
		key = t.hmacKey
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
		key = t.rsaPubKey
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
		key = t.rsaPubKey
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
		key = t.rsaPubKey
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", t.method)
	}

	// Parse the token with verification
	token, err := jwt.ParseWithClaims(encryptedToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify that the signing method matches the expected one
		if token.Method != signingMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// GetRefreshTokenData extracts and returns the user ID and expiration time from a refresh token
// It parses the token and validates the type and claims, returning an error if any validation fails
func (t *token) GetRefreshTokenData(encryptedToken string) (int, time.Time, error) {
	claims, err := t.parseTokenWithVerification(encryptedToken)
	if err != nil {
		return 0, time.Time{}, err // Return error if token parsing fails
	}

	// Validate the token type, should be "refresh"
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		return 0, time.Time{}, errors.New("token type (`type`) not found or mismatch in token")
	}

	// Extract the user ID and expiration time from the claims
	uid, ok := claims["uid"].(float64)
	if !ok {
		return 0, time.Time{}, errors.New("user id (`uid`) not found in token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, time.Time{}, errors.New("expiration time (`exp`) not found in token")
	}

	return int(uid), time.Unix(int64(exp), 0), nil // Return user ID and expiration time
}
