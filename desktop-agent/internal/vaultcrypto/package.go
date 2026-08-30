package vaultcrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const CryptoVersion = 2

// Package is the v2 encrypted credential package stored by the vault.
type Package struct {
	CredentialID             string `json:"credential_id"`
	Origin                   string `json:"origin"`
	Ciphertext               string `json:"ciphertext"`
	CipherNonce              string `json:"cipher_nonce"`
	WrappedDEK               string `json:"wrapped_dek"`
	WrapNonce                string `json:"wrap_nonce"`
	WrapEphemeralPublicKey   string `json:"wrap_ephemeral_public_key"`
	PixelVaultKeyID          string `json:"pixel_vault_key_id"`
	CryptoVersion            int    `json:"crypto_version"`
}

// Canonical returns the canonical byte representation used for package hashing.
func Canonical(pkg *Package) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "universal-auth:vault-package:v2\n")
	fmt.Fprintf(&buf, "credential_id=%s\n", b64urlutf8(pkg.CredentialID))
	fmt.Fprintf(&buf, "origin=%s\n", b64urlutf8(pkg.Origin))
	fmt.Fprintf(&buf, "ciphertext=%s\n", pkg.Ciphertext)
	fmt.Fprintf(&buf, "cipher_nonce=%s\n", pkg.CipherNonce)
	fmt.Fprintf(&buf, "wrapped_dek=%s\n", pkg.WrappedDEK)
	fmt.Fprintf(&buf, "wrap_nonce=%s\n", pkg.WrapNonce)
	fmt.Fprintf(&buf, "wrap_ephemeral_public_key=%s\n", pkg.WrapEphemeralPublicKey)
	fmt.Fprintf(&buf, "pixel_vault_key_id=%s\n", pkg.PixelVaultKeyID)
	fmt.Fprintf(&buf, "crypto_version=%d\n", pkg.CryptoVersion)
	return buf.Bytes()
}

// Hash returns the unpadded Base64URL SHA-256 hash of the canonical package.
func Hash(pkg *Package) string {
	sum := sha256.Sum256(Canonical(pkg))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func b64urlutf8(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
