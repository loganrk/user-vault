package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"
	"user-vault/internal/core/port"
	"user-vault/internal/utils"

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
func New(method string, hmacKey []byte, privateKeyPath, publicKeyPath string) (port.Token, error) {
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var err error
	switch method {
	case "HMAC", "HS256", "HS384", "HS512":
		if string(hmacKey) == "" {
			return nil, fmt.Errorf("HMAC key is missing for JWT method %s", method)
		}
	case "RSA", "RS256", "RS384", "RS512":
		privateKeyPath := os.Getenv("JWT_RSA_PRIVATE_KEY_PATH")
		publicKeyPath := os.Getenv("JWT_RSA_PUBLIC_KEY_PATH")

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

// parseTokenWithoutVerification parses the token without verification (no signature validation)
// This method allows for extracting claims without verifying the authenticity of the token
func (t *token) parseTokenWithoutVerification(encryptedToken string) (jwt.MapClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(encryptedToken, jwt.MapClaims{})
	if err != nil {
		return nil, err // Return error if token parsing fails
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil // Return the claims if successfully parsed
	}

	return nil, errors.New("invalid token claims") // Return error if claims are not valid
}

// GetRefreshTokenData extracts and returns the user ID and expiration time from a refresh token
// It parses the token and validates the type and claims, returning an error if any validation fails
func (t *token) GetRefreshTokenData(encryptedToken string) (int, time.Time, error) {
	claims, err := t.parseTokenWithoutVerification(encryptedToken)
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
