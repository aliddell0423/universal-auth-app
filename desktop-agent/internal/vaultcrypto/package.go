package vaultcrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	CryptoVersionV2 = 2
	CryptoVersionV3 = 3
	// CryptoVersion is the version produced by Encrypt.
	CryptoVersion = CryptoVersionV3
)

// Package kinds.
const (
	KindLogin  = "login"
	KindSecret = "secret"
	KindSSHKey = "ssh_key"
)

// ValidKind reports whether kind is a supported package kind.
func ValidKind(kind string) bool {
	switch kind {
	case KindLogin, KindSecret, KindSSHKey:
		return true
	}
	return false
}

// Package is the encrypted credential package stored by the vault.
// CryptoVersion 2 packages use Origin and the {username,password} plaintext.
// CryptoVersion 3 packages use Kind and Resource with a {fields:{...}} plaintext.
type Package struct {
	CredentialID           string `json:"credential_id"`
	Kind                   string `json:"kind,omitempty"`
	Resource               string `json:"resource,omitempty"`
	Origin                 string `json:"origin,omitempty"`
	Ciphertext             string `json:"ciphertext"`
	CipherNonce            string `json:"cipher_nonce"`
	WrappedDEK             string `json:"wrapped_dek"`
	WrapNonce              string `json:"wrap_nonce"`
	WrapEphemeralPublicKey string `json:"wrap_ephemeral_public_key"`
	PixelVaultKeyID        string `json:"pixel_vault_key_id"`
	CryptoVersion          int    `json:"crypto_version"`
}

// Res returns the lookup resource for the package: Resource for v3,
// Origin for legacy v2 packages.
func (p *Package) Res() string {
	if p.Resource != "" {
		return p.Resource
	}
	return p.Origin
}

// Canonical returns the canonical byte representation used for package hashing.
func Canonical(pkg *Package) []byte {
	if pkg.CryptoVersion == CryptoVersionV2 {
		return canonicalV2(pkg)
	}
	return canonicalV3(pkg)
}

func canonicalV2(pkg *Package) []byte {
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

func canonicalV3(pkg *Package) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "universal-auth:vault-package:v3\n")
	fmt.Fprintf(&buf, "credential_id=%s\n", b64urlutf8(pkg.CredentialID))
	fmt.Fprintf(&buf, "kind=%s\n", b64urlutf8(pkg.Kind))
	fmt.Fprintf(&buf, "resource=%s\n", b64urlutf8(pkg.Resource))
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
