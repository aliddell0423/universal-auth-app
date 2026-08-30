package vaultcrypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey uses HKDF-SHA256 to derive a key of the requested length.
func DeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
