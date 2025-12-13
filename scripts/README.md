# AES Encrypt / Decrypt CLI (Go)

Simple command-line usage guide for encrypting and decrypting text using AES with a shared crypto key.

---

## Requirements

- Go 1.18 or newer

---

## Dependency

This tool relies on the following AES utility package:

```
github.com/loganrk/utils-go/adapters/cipher/aes
```

---

## How to Use

### Encrypt Text

Run the encrypt program:

```bash
go run encrypt/encrypt.go
```

You will be prompted to enter:

1. **Crypto key** – secret key used for encryption
2. **Text to encrypt** – plaintext input

Example session:

```
Enter the crypto key: my-secret-key
Enter text to encrypt: hello world
Encrypted: U2FsdGVkX1...
```

You can continue encrypting multiple values without restarting the program.

---

### Decrypt Text

Run the decrypt program:

```bash
go run decrypt/decrypt.go
```

You will be prompted to enter:

1. **Crypto key** – must be the same key used during encryption
2. **Text to decrypt** – encrypted text

Example session:

```
Enter the crypto key: my-secret-key
Enter text to decrypt: U2FsdGVkX1...
Decrypted: hello world
```

---

## Important Notes

- The **same crypto key** must be used for both encryption and decryption
- Input is trimmed automatically
- Any error during encryption or decryption will stop the program

---

## Security Notice

This tool is intended for basic usage and learning purposes.

- Do not expose or hard-code secret keys
- Review the AES implementation before using in production environments

---

## License

MIT License
