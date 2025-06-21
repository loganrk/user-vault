package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	cipherAes "github.com/loganrk/utils-go/adapters/cipher/aes"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the crypto key: ")
	cryptoKey, _ := reader.ReadString('\n')
	cryptoKey = strings.TrimSpace(cryptoKey)
	cipherIns := cipherAes.New(cryptoKey)

	for {
		fmt.Print("Enter text to encrypt: ")
		plaintext, _ := reader.ReadString('\n')
		plaintext = strings.TrimSpace(plaintext)
		encrypted, err := cipherIns.Encrypt(plaintext)
		if err != nil {
			log.Fatalf("Error encrypting: %v", err)
			return
		}
		fmt.Printf("Encrypted: %s\n", encrypted)
	}

}
