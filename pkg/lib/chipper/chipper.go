package chipper

import (
	"mayilon/pkg/lib/chipper/aes"
)

type Chipper interface {
	Encrypt(text string) (string, error)
	Decrypt(cryptoText string) (string, error)
}

func New(CryptoKey string) Chipper {
	return aes.New(CryptoKey)

}
