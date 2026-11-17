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

// CredentialPlaintext is the legacy v2 JSON credential payload.
type CredentialPlaintext struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Plaintext is the v3 JSON payload: a map of named fields.
type Plaintext struct {
	Fields map[string]string `json:"fields"`
}

// plainPayload wraps fields for JSON marshaling.
type plainPayload struct {
	Fields map[string]string `json:"fields"`
}

func marshalPlaintext(fields map[string]string) ([]byte, error) {
	return json.Marshal(plainPayload{Fields: fields})
}

// EncryptV2 builds a legacy v2 credential package (username/password, origin).
func EncryptV2(pt *CredentialPlaintext, id, origin, pixelVaultKeyID string, pixelVaultPub *ecdsa.PublicKey) (*Package, []byte, error) {
	payload, err := json.Marshal(pt)
	if err != nil {
		return nil, nil, err
	}
	return encryptPackage(CryptoVersionV2, payload, id, "", origin, pixelVaultKeyID, pixelVaultPub)
}

// Encrypt builds a v3 package for the given kind and resource.
func Encrypt(fields map[string]string, kind, resource, id, pixelVaultKeyID string, pixelVaultPub *ecdsa.PublicKey) (*Package, []byte, error) {
	if !ValidKind(kind) {
		return nil, nil, fmt.Errorf("unsupported kind %q", kind)
	}
	payload, err := marshalPlaintext(fields)
	if err != nil {
		return nil, nil, err
	}
	return encryptPackage(CryptoVersionV3, payload, id, kind, resource, pixelVaultKeyID, pixelVaultPub)
}

func encryptPackage(version int, payload []byte, id, kind, resource, pixelVaultKeyID string, pixelVaultPub *ecdsa.PublicKey) (*Package, []byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, err
	}

	ciphertext, cipherNonce, err := GCMEncrypt(dek, payload, credentialAAD(version, id, kind, resource, pixelVaultKeyID))
	if err != nil {
		return nil, nil, err
	}

	wrapPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	wrapKey, err := buildWrapKey(version, wrapPriv, pixelVaultPub, id, kind, resource, pixelVaultKeyID)
	if err != nil {
		return nil, nil, err
	}

	wrapPubDER, err := x509.MarshalPKIXPublicKey(&wrapPriv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	wrapPubB64 := base64.RawURLEncoding.EncodeToString(wrapPubDER)

	wrapped, wrapNonce, err := GCMEncrypt(wrapKey, dek, wrapAAD(version, id, kind, resource, pixelVaultKeyID, wrapPubB64))
	if err != nil {
		return nil, nil, err
	}

	pkg := &Package{
		CredentialID:           id,
		Kind:                   kind,
		Resource:               resource,
		Origin:                 originForVersion(version, resource),
		Ciphertext:             base64.RawURLEncoding.EncodeToString(ciphertext),
		CipherNonce:            base64.RawURLEncoding.EncodeToString(cipherNonce),
		WrappedDEK:             base64.RawURLEncoding.EncodeToString(wrapped),
		WrapNonce:              base64.RawURLEncoding.EncodeToString(wrapNonce),
		WrapEphemeralPublicKey: wrapPubB64,
		PixelVaultKeyID:        pixelVaultKeyID,
		CryptoVersion:          version,
	}
	return pkg, dek, nil
}

func originForVersion(version int, resource string) string {
	if version == CryptoVersionV2 {
		return resource
	}
	return ""
}

// Decrypt unwraps and decrypts a package (v2 or v3) given the Pixel vault private key.
func Decrypt(pkg *Package, pixelVaultPriv *ecdsa.PrivateKey) (*Plaintext, error) {
	if pkg.CryptoVersion != CryptoVersionV2 && pkg.CryptoVersion != CryptoVersionV3 {
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
	kind := pkg.Kind
	if pkg.CryptoVersion == CryptoVersionV2 {
		kind = KindLogin
	}
	wrapKey, err := buildWrapKeyForUnwrap(pkg.CryptoVersion, wrapPub, pixelVaultPriv, pkg.CredentialID, kind, pkg.Res(), pkg.PixelVaultKeyID)
	if err != nil {
		return nil, err
	}
	dek, err := GCMDecrypt(wrapKey, mustB64(pkg.WrappedDEK), mustB64(pkg.WrapNonce), wrapAAD(pkg.CryptoVersion, pkg.CredentialID, kind, pkg.Res(), pkg.PixelVaultKeyID, pkg.WrapEphemeralPublicKey))
	if err != nil {
		return nil, err
	}
	plaintext, err := GCMDecrypt(dek, mustB64(pkg.Ciphertext), mustB64(pkg.CipherNonce), credentialAAD(pkg.CryptoVersion, pkg.CredentialID, kind, pkg.Res(), pkg.PixelVaultKeyID))
	if err != nil {
		return nil, err
	}
	return parsePlaintext(pkg.CryptoVersion, plaintext)
}

func parsePlaintext(version int, plaintext []byte) (*Plaintext, error) {
	if version == CryptoVersionV2 {
		var pt CredentialPlaintext
		if err := json.Unmarshal(plaintext, &pt); err != nil {
			return nil, err
		}
		return &Plaintext{Fields: map[string]string{
			"username": pt.Username,
			"password": pt.Password,
		}}, nil
	}
	var payload plainPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, err
	}
	if payload.Fields == nil {
		return nil, fmt.Errorf("plaintext missing fields")
	}
	return &Plaintext{Fields: payload.Fields}, nil
}

func buildWrapKey(version int, wrapPriv *ecdsa.PrivateKey, pixelVaultPub *ecdsa.PublicKey, id, kind, resource, pixelVaultKeyID string) ([]byte, error) {
	return deriveSharedKey(version, wrapPriv, pixelVaultPub, id, kind, resource, pixelVaultKeyID)
}

func buildWrapKeyForUnwrap(version int, wrapPub *ecdsa.PublicKey, pixelVaultPriv *ecdsa.PrivateKey, id, kind, resource, pixelVaultKeyID string) ([]byte, error) {
	return deriveSharedKeyWithScalar(version, wrapPub, pixelVaultPriv.D, id, kind, resource, pixelVaultKeyID)
}

func deriveSharedKey(version int, localPriv *ecdsa.PrivateKey, peerPub *ecdsa.PublicKey, id, kind, resource, pixelVaultKeyID string) ([]byte, error) {
	return deriveSharedKeyWithScalar(version, peerPub, localPriv.D, id, kind, resource, pixelVaultKeyID)
}

func deriveSharedKeyWithScalar(version int, peerPub *ecdsa.PublicKey, scalar *big.Int, id, kind, resource, pixelVaultKeyID string) ([]byte, error) {
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
	return deriveWrapKey(version, secret, id, kind, resource, pixelVaultKeyID)
}

func deriveWrapKey(version int, secret []byte, id, kind, resource, pixelVaultKeyID string) ([]byte, error) {
	saltMsg := fmt.Sprintf("universal-auth:vault-wrap-salt:v%d\ncredential_id=%s\n", version, id)
	info := fmt.Sprintf("universal-auth:vault-wrap-key:v%d", version)
	if version == CryptoVersionV3 {
		saltMsg += fmt.Sprintf("kind=%s\nresource=%s\npixel_vault_key_id=%s\n", kind, resource, pixelVaultKeyID)
	} else {
		saltMsg += fmt.Sprintf("origin=%s\npixel_vault_key_id=%s\n", resource, pixelVaultKeyID)
	}
	salt := sha256.Sum256([]byte(saltMsg))
	return DeriveKey(secret, salt[:], []byte(info), 32)
}

func GCMEncrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {
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

func credentialAAD(version int, id, kind, resource, pixelVaultKeyID string) []byte {
	if version == CryptoVersionV3 {
		return []byte(fmt.Sprintf("universal-auth:vault-credential:v3\ncredential_id=%s\nkind=%s\nresource=%s\npixel_vault_key_id=%s\n", id, kind, resource, pixelVaultKeyID))
	}
	return []byte(fmt.Sprintf("universal-auth:vault-credential:v2\ncredential_id=%s\norigin=%s\npixel_vault_key_id=%s\n", id, resource, pixelVaultKeyID))
}

func wrapAAD(version int, id, kind, resource, pixelVaultKeyID, wrapEphemeralPub string) []byte {
	if version == CryptoVersionV3 {
		return []byte(fmt.Sprintf("universal-auth:vault-dek:v3\ncredential_id=%s\nkind=%s\nresource=%s\npixel_vault_key_id=%s\nwrap_ephemeral_public_key=%s\n", id, kind, resource, pixelVaultKeyID, wrapEphemeralPub))
	}
	return []byte(fmt.Sprintf("universal-auth:vault-dek:v2\ncredential_id=%s\norigin=%s\npixel_vault_key_id=%s\nwrap_ephemeral_public_key=%s\n", id, resource, pixelVaultKeyID, wrapEphemeralPub))
}

// DecryptCredentialWithDEK decrypts the payload of a package with an
// already-unwrapped DEK, returning the parsed plaintext.
func DecryptCredentialWithDEK(pkg *Package, dek []byte) (*Plaintext, error) {
	kind := pkg.Kind
	if pkg.CryptoVersion == CryptoVersionV2 {
		kind = KindLogin
	}
	plaintext, err := GCMDecrypt(dek, mustB64(pkg.Ciphertext), mustB64(pkg.CipherNonce), credentialAAD(pkg.CryptoVersion, pkg.CredentialID, kind, pkg.Res(), pkg.PixelVaultKeyID))
	if err != nil {
		return nil, err
	}
	return parsePlaintext(pkg.CryptoVersion, plaintext)
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
