package utils

import (
	"math/rand"
	"strings"
	"unicode"

	"github.com/google/uuid"
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

func (u *utils) GenerateUUID() string {
	return uuid.NewString() // UUID v4
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

// ExtractBearerToken extracts the token from the Authorization header by splitting it into "Bearer <token>" format.
func ExtractBearerToken(token string) string {
	// Split the Authorization header to extract the token part.
	parts := strings.SplitN(token, " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1] // Return the token part of the "Bearer <token>" format.
	}
	return "" // Return an empty string if the token is not in the correct format.
}
