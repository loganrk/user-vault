package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"unicode"
)

type utils struct{}

func New() *utils {
	return &utils{}
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const charsetForOtp = "0123456789"

// GenerateString returns a random string of the given length
// using characters from the predefined charset.
func (u *utils) GenerateString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func (u *utils) GenerateOTPString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charsetForOtp[rand.Intn(len(charsetForOtp))]
	}
	return string(result)
}

func GenerateString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// FindFileContent reads the file at the given path and returns its contents as a string.
// Returns an error if the file cannot be read.
func FindFileContent(path string) (string, error) {
	templateBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(templateBytes), nil
}

// HasLowercase checks if the given string contains at least one lowercase letter.
func HasLowercase(s string) bool {
	for _, c := range s {
		if unicode.IsLower(c) {
			return true
		}
	}
	return false
}

// HasUppercase checks if the given string contains at least one uppercase letter.
func HasUppercase(s string) bool {
	for _, c := range s {
		if unicode.IsUpper(c) {
			return true
		}
	}
	return false
}

// HasDigit checks if the given string contains at least one digit.
func HasDigit(s string) bool {
	for _, c := range s {
		if unicode.IsDigit(c) {
			return true
		}
	}
	return false
}

// HasSpecialChar checks if the given string contains at least one special character
// from the predefined set: @$!%*?&
func HasSpecialChar(s string) bool {
	specialChars := "@$!%*?&"
	for _, c := range s {
		if containsRune(specialChars, c) {
			return true
		}
	}
	return false
}

// containsRune checks if the rune `r` exists in the string `s`.
func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

// Function to load RSA public key from a PEM file
func LoadRSAPubKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	// Read the PEM file
	pemData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read public key file: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	// Parse the public key
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse RSA public key: %v", err)
	}

	return key, nil
}

func LoadRSAPrivKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	// Read the PEM file
	pemData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key file: %v", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	// Parse the private key
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse RSA private key: %v", err)
	}

	return privKey, nil
}

// ExtractBearerToken extracts the token from the Authorization header by splitting it into "Bearer <token>" format.
func ExtractBearerToken(token string) string {
	// Split the Authorization header to extract the token part.
	parts := strings.SplitN(token, " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1] // Return the token part of the "Bearer <token>" format.
	}
	return "" // Return an empty string if the token is not in the correct format.
}
