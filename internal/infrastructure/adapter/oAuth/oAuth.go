package oAuth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"google.golang.org/api/idtoken"
)

// oauthAdapter verifies OAuth tokens from multiple providers
type oauthAdapter struct {
	httpClient        *http.Client
	appleClientID     string
	googleClientID    string
	microsoftClientID string
}

// Apple public keys response
type appleKeysResponse struct {
	Keys []jwk `json:"keys"`
}

// JSON Web Key used by Apple
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// creates a new OAuth adapter with provider client IDs
func New(appleClientID, googleClientID, microsoftClientID string) *oauthAdapter {
	return &oauthAdapter{
		httpClient:        http.DefaultClient,
		appleClientID:     appleClientID,
		googleClientID:    googleClientID,
		microsoftClientID: microsoftClientID,
	}
}

// VerifyToken validates a provider token and extracts user identity
func (a *oauthAdapter) VerifyToken(
	ctx context.Context,
	provider string,
	token string,
) (email string, name string, err error) {

	switch strings.ToLower(provider) {
	case "google":
		return a.verifyGoogle(ctx, token)

	case "microsoft":
		return a.verifyMicrosoft(ctx, token)

	case "apple":
		return a.verifyApple(ctx, token)

	default:
		return "", "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

// verifyGoogle validates Google ID token
func (a *oauthAdapter) verifyGoogle(ctx context.Context, token string) (string, string, error) {
	if a.googleClientID == "" {
		return "", "", fmt.Errorf("google client id not configured")
	}

	payload, err := idtoken.Validate(ctx, token, a.googleClientID)
	if err != nil {
		return "", "", fmt.Errorf("google token validation failed: %w", err)
	}

	email, _ := payload.Claims["email"].(string)
	givenName, _ := payload.Claims["given_name"].(string)
	familyName, _ := payload.Claims["family_name"].(string)

	return email, strings.TrimSpace(givenName + " " + familyName), nil
}

// verifyMicrosoft validates Microsoft (Azure AD) ID token
func (a *oauthAdapter) verifyMicrosoft(ctx context.Context, token string) (string, string, error) {
	if a.microsoftClientID == "" {
		return "", "", fmt.Errorf("microsoft client id not configured")
	}

	payload, err := idtoken.Validate(ctx, token, a.microsoftClientID)
	if err != nil {
		return "", "", fmt.Errorf("microsoft token validation failed: %w", err)
	}

	email, _ := payload.Claims["preferred_username"].(string)
	if email == "" {
		email, _ = payload.Claims["email"].(string)
	}

	name, _ := payload.Claims["name"].(string)

	return email, name, nil
}

// verifyApple validates Apple ID token using Apple's public keys
func (a *oauthAdapter) verifyApple(ctx context.Context, token string) (string, string, error) {
	if a.appleClientID == "" {
		return "", "", fmt.Errorf("apple client id not configured")
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}

		// Fetch Apple public keys
		resp, err := a.httpClient.Get("https://appleid.apple.com/auth/keys")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var keys appleKeysResponse
		if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
			return nil, err
		}

		// Match key by kid
		kid := t.Header["kid"]
		for _, key := range keys.Keys {
			if key.Kid == kid {
				return jwt.ParseRSAPublicKeyFromPEM(a.jwkToPEM(key))
			}
		}
		return nil, fmt.Errorf("apple public key not found")
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, keyFunc)
	if err != nil || !parsed.Valid {
		return "", "", fmt.Errorf("invalid apple token")
	}

	// Validate issuer and audience
	if claims["iss"] != "https://appleid.apple.com" {
		return "", "", fmt.Errorf("invalid issuer")
	}

	if claims["aud"] != a.appleClientID {
		return "", "", fmt.Errorf("invalid audience")
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string) // Only present on first login

	return email, name, nil
}

// jwkToPEM converts Apple JWK to PEM-encoded RSA public key
func (a *oauthAdapter) jwkToPEM(key jwk) []byte {
	nb, _ := base64.RawURLEncoding.DecodeString(key.N)
	eb, _ := base64.RawURLEncoding.DecodeString(key.E)

	pubKey := rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(new(big.Int).SetBytes(eb).Int64()),
	}

	pubASN1, _ := x509.MarshalPKIXPublicKey(&pubKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
}
