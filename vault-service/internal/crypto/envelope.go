package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const CryptoVersion = 1

type Record struct {
	Ciphertext    []byte
	CipherNonce   []byte
	WrappedDEK    []byte
	WrapNonce     []byte
	CryptoVersion int
}

// Encrypt encrypts plaintext with a fresh random DEK and wraps that DEK with kek.
func Encrypt(plaintext []byte, id, origin string, kek []byte) (*Record, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must be 32 bytes")
	}

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}

	ciphertext, cipherNonce, err := gcmEncrypt(dek, plaintext, credentialAAD(id, origin))
	if err != nil {
		return nil, err
	}

	wrapped, wrapNonce, err := gcmEncrypt(kek, dek, dekAAD(id, origin))
	if err != nil {
		return nil, err
	}

	return &Record{
		Ciphertext:    ciphertext,
		CipherNonce:   cipherNonce,
		WrappedDEK:    wrapped,
		WrapNonce:     wrapNonce,
		CryptoVersion: CryptoVersion,
	}, nil
}

// Decrypt unwraps the DEK and then decrypts the credential plaintext.
func Decrypt(record *Record, id, origin string, kek []byte) ([]byte, error) {
	if record.CryptoVersion != CryptoVersion {
		return nil, fmt.Errorf("unsupported crypto version %d", record.CryptoVersion)
	}

	dek, err := gcmDecrypt(kek, record.WrappedDEK, record.WrapNonce, dekAAD(id, origin))
	if err != nil {
		return nil, err
	}

	plaintext, err := gcmDecrypt(dek, record.Ciphertext, record.CipherNonce, credentialAAD(id, origin))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func gcmEncrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := g.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

func gcmDecrypt(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ciphertext, aad)
}

func credentialAAD(id, origin string) []byte {
	return []byte("universal-auth:vault:credential:v1\nid=" + id + "\norigin=" + origin)
}

func dekAAD(id, origin string) []byte {
	return []byte("universal-auth:vault:dek:v1\nid=" + id + "\norigin=" + origin)
}
