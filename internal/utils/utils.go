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
	"unicode"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateRandomString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func FindFileContent(path string) (string, error) {
	templateBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(templateBytes), nil
}

func HasLowercase(s string) bool {
	for _, c := range s {
		if unicode.IsLower(c) {
			return true
		}
	}
	return false
}

func HasUppercase(s string) bool {
	for _, c := range s {
		if unicode.IsUpper(c) {
			return true
		}
	}
	return false
}

func HasDigit(s string) bool {
	for _, c := range s {
		if unicode.IsDigit(c) {
			return true
		}
	}
	return false
}

func HasSpecialChar(s string) bool {
	specialChars := "@$!%*?&"
	for _, c := range s {
		if containsRune(specialChars, c) {
			return true
		}
	}
	return false
}

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
