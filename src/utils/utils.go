package utils

import (
	"math/rand"
	"os"
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
