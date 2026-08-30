package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

// CredentialPlaintext is the JSON credential payload.
type CredentialPlaintext struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Encrypt builds a v2 credential package.
func Encrypt(pt *CredentialPlaintext, id, origin, pixelVaultKeyID string, pixelVaultPub *ecdsa.PublicKey) (*Package, []byte, error) {
	payload, err := json.Marshal(pt)
	if err != nil {
		return nil, nil, err
	}

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, err
	}

	ciphertext, cipherNonce, err := gcmEncrypt(dek, payload, credentialAAD(id, origin, pixelVaultKeyID))
	if err != nil {
		return nil, nil, err
	}

	wrapPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	wrapKey, err := buildWrapKey(wrapPriv, pixelVaultPub, id, origin, pixelVaultKeyID)
	if err != nil {
		return nil, nil, err
	}

	wrapPubDER, err := x509.MarshalPKIXPublicKey(&wrapPriv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	wrapPubB64 := base64.RawURLEncoding.EncodeToString(wrapPubDER)

	wrapped, wrapNonce, err := gcmEncrypt(wrapKey, dek, wrapAAD(id, origin, pixelVaultKeyID, wrapPubB64))
	if err != nil {
		return nil, nil, err
	}

	pkg := &Package{
		CredentialID:           id,
		Origin:                 origin,
		Ciphertext:             base64.RawURLEncoding.EncodeToString(ciphertext),
		CipherNonce:            base64.RawURLEncoding.EncodeToString(cipherNonce),
		WrappedDEK:             base64.RawURLEncoding.EncodeToString(wrapped),
		WrapNonce:              base64.RawURLEncoding.EncodeToString(wrapNonce),
		WrapEphemeralPublicKey: wrapPubB64,
		PixelVaultKeyID:        pixelVaultKeyID,
		CryptoVersion:          CryptoVersion,
	}
	return pkg, dek, nil
}

// Decrypt unwraps and decrypts a v2 package given the Pixel vault private key.
func Decrypt(pkg *Package, pixelVaultPriv *ecdsa.PrivateKey) (*CredentialPlaintext, error) {
	if pkg.CryptoVersion != CryptoVersion {
		return nil, fmt.Errorf("unsupported crypto version %d", pkg.CryptoVersion)
	}
	wrapPriv, err := x509.ParsePKIXPublicKey(mustB64(pkg.WrapEphemeralPublicKey))
	if err != nil {
		return nil, fmt.Errorf("wrap public key: %w", err)
	}
	wrapPub, ok := wrapPriv.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrap public key is not ECDSA")
	}
	wrapKey, err := buildWrapKeyForUnwrap(wrapPub, pixelVaultPriv, pkg.CredentialID, pkg.Origin, pkg.PixelVaultKeyID)
	if err != nil {
		return nil, err
	}
	dek, err := GCMDecrypt(wrapKey, mustB64(pkg.WrappedDEK), mustB64(pkg.WrapNonce), wrapAAD(pkg.CredentialID, pkg.Origin, pkg.PixelVaultKeyID, pkg.WrapEphemeralPublicKey))
	if err != nil {
		return nil, err
	}
	plaintext, err := GCMDecrypt(dek, mustB64(pkg.Ciphertext), mustB64(pkg.CipherNonce), credentialAAD(pkg.CredentialID, pkg.Origin, pkg.PixelVaultKeyID))
	if err != nil {
		return nil, err
	}
	var pt CredentialPlaintext
	if err := json.Unmarshal(plaintext, &pt); err != nil {
		return nil, err
	}
	return &pt, nil
}

func buildWrapKey(wrapPriv *ecdsa.PrivateKey, pixelVaultPub *ecdsa.PublicKey, id, origin, pixelVaultKeyID string) ([]byte, error) {
	return deriveSharedKey(wrapPriv, pixelVaultPub, id, origin, pixelVaultKeyID)
}

func buildWrapKeyForUnwrap(wrapPub *ecdsa.PublicKey, pixelVaultPriv *ecdsa.PrivateKey, id, origin, pixelVaultKeyID string) ([]byte, error) {
	return deriveSharedKeyWithScalar(wrapPub, pixelVaultPriv.D, id, origin, pixelVaultKeyID)
}

func deriveSharedKey(localPriv *ecdsa.PrivateKey, peerPub *ecdsa.PublicKey, id, origin, pixelVaultKeyID string) ([]byte, error) {
	return deriveSharedKeyWithScalar(peerPub, localPriv.D, id, origin, pixelVaultKeyID)
}

func deriveSharedKeyWithScalar(peerPub *ecdsa.PublicKey, scalar *big.Int, id, origin, pixelVaultKeyID string) ([]byte, error) {
	priv, err := ecdh.P256().NewPrivateKey(pad32(scalar.Bytes()))
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(elliptic.Marshal(peerPub.Curve, peerPub.X, peerPub.Y))
	if err != nil {
		return nil, err
	}
	secret, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return deriveWrapKey(secret, id, origin, pixelVaultKeyID)
}

func deriveWrapKey(secret []byte, id, origin, pixelVaultKeyID string) ([]byte, error) {
	salt := sha256.Sum256([]byte(fmt.Sprintf("universal-auth:vault-wrap-salt:v2\ncredential_id=%s\norigin=%s\npixel_vault_key_id=%s\n", id, origin, pixelVaultKeyID)))
	info := []byte("universal-auth:vault-wrap-key:v2")
	return DeriveKey(secret, salt[:], info, 32)
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

func GCMDecrypt(key, ciphertext, nonce, aad []byte) ([]byte, error) {
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

func credentialAAD(id, origin, pixelVaultKeyID string) []byte {
	return []byte(fmt.Sprintf("universal-auth:vault-credential:v2\ncredential_id=%s\norigin=%s\npixel_vault_key_id=%s\n", id, origin, pixelVaultKeyID))
}

func wrapAAD(id, origin, pixelVaultKeyID, wrapEphemeralPub string) []byte {
	return []byte(fmt.Sprintf("universal-auth:vault-dek:v2\ncredential_id=%s\norigin=%s\npixel_vault_key_id=%s\nwrap_ephemeral_public_key=%s\n", id, origin, pixelVaultKeyID, wrapEphemeralPub))
}

func DecryptCredentialWithDEK(pkg *Package, dek []byte) (*CredentialPlaintext, error) {
	plaintext, err := GCMDecrypt(dek, mustB64(pkg.Ciphertext), mustB64(pkg.CipherNonce), credentialAAD(pkg.CredentialID, pkg.Origin, pkg.PixelVaultKeyID))
	if err != nil {
		return nil, err
	}
	var pt CredentialPlaintext
	if err := json.Unmarshal(plaintext, &pt); err != nil {
		return nil, err
	}
	return &pt, nil
}

func pad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func mustB64(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}
