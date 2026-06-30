package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type EncryptedPayload struct {
	Ciphertext []byte
	Key        []byte
	IV         []byte
}

func EncryptAES256CBC(plaintext []byte) (*EncryptedPayload, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generating iv: %w", err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return &EncryptedPayload{
		Ciphertext: ciphertext,
		Key:        key,
		IV:         iv,
	}, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func FormatByteArray(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, len(b)*6)
	for i, v := range b {
		if i > 0 {
			out = append(out, ',', ' ')
		}
		out = append(out, fmt.Sprintf("0x%02x", v)...)
	}
	return string(out)
}
