package main

import (
	"bufio"
	"fmt"
	"log"
	"mayilon/pkg/lib/chipper"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the crypto key: ")
	cryptoKey, _ := reader.ReadString('\n')
	cryptoKey = strings.TrimSpace(cryptoKey)
	chipperIns := chipper.New(cryptoKey)

	for {
		fmt.Print("Enter text to encrypt: ")
		plaintext, _ := reader.ReadString('\n')
		plaintext = strings.TrimSpace(plaintext)
		encrypted, err := chipperIns.Encrypt(plaintext)
		if err != nil {
			log.Fatalf("Error encrypting: %v", err)
			return
		}
		fmt.Printf("Encrypted: %s\n", encrypted)
	}

}
