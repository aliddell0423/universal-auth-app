package vaultcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func randomPixelKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(der)
	return priv, hex.EncodeToString(sum[:])
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv, keyID := randomPixelKey(t)
	pt := &CredentialPlaintext{Username: "u", Password: "p"}
	pkg, _, err := EncryptV2(pt, "aabbcc", "https://github.com", keyID, &priv.PublicKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := Decrypt(pkg, priv)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got.Fields["username"] != pt.Username || got.Fields["password"] != pt.Password {
		t.Fatalf("got %v", got)
	}
}

func TestPackageHash(t *testing.T) {
	priv, keyID := randomPixelKey(t)
	pkg, _, _ := EncryptV2(&CredentialPlaintext{Username: "u", Password: "p"}, "id1", "https://github.com", keyID, &priv.PublicKey)
	if pkg.Ciphertext == "" {
		t.Fatal("empty ciphertext")
	}
	h := Hash(pkg)
	if _, err := base64.RawURLEncoding.DecodeString(h); err != nil {
		t.Fatalf("hash not raw base64url: %v", err)
	}
	// Same inputs should not produce the same hash due to randomness.
	pkg2, _, _ := EncryptV2(&CredentialPlaintext{Username: "u", Password: "p"}, "id1", "https://github.com", keyID, &priv.PublicKey)
	if Hash(pkg) == Hash(pkg2) {
		t.Fatal("hash should be different for different random values")
	}
}

func TestTamperedCiphertext(t *testing.T) {
	priv, keyID := randomPixelKey(t)
	pkg, _, _ := EncryptV2(&CredentialPlaintext{Username: "u", Password: "p"}, "id1", "https://github.com", keyID, &priv.PublicKey)
	b, _ := base64.RawURLEncoding.DecodeString(pkg.Ciphertext)
	b[0] ^= 0xff
	pkg.Ciphertext = base64.RawURLEncoding.EncodeToString(b)
	_, err := Decrypt(pkg, priv)
	if err == nil {
		t.Fatal("expected decryption failure for tampered ciphertext")
	}
}

func TestWrongPixelPrivateKey(t *testing.T) {
	priv, keyID := randomPixelKey(t)
	wrong, _ := randomPixelKey(t)
	pkg, _, _ := EncryptV2(&CredentialPlaintext{Username: "u", Password: "p"}, "id1", "https://github.com", keyID, &priv.PublicKey)
	_, err := Decrypt(pkg, wrong)
	if err == nil {
		t.Fatal("expected failure with wrong Pixel private key")
	}
}

func TestHKDFRFC5869Vector(t *testing.T) {
	// RFC 5869 test vector 1.
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	okm, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	got, err := DeriveKey(ikm, salt, info, 42)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if string(got) != string(okm) {
		t.Fatalf("hkdf mismatch:\n%x\nwant\n%x", got, okm)
	}
}

func TestEncryptV3RoundTrip(t *testing.T) {
	priv, keyID := randomPixelKey(t)
	fields := map[string]string{
		"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
		"comment":     "test key",
	}
	pkg, _, err := Encrypt(fields, KindSSHKey, "ssh/gmail", "a1b2c3", keyID, &priv.PublicKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if pkg.CryptoVersion != CryptoVersionV3 || pkg.Kind != KindSSHKey || pkg.Resource != "ssh/gmail" {
		t.Fatalf("unexpected package: %+v", pkg)
	}
	if pkg.Origin != "" {
		t.Fatalf("v3 package must not set origin: %q", pkg.Origin)
	}
	got, err := Decrypt(pkg, priv)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got.Fields["private_key"] != fields["private_key"] || got.Fields["comment"] != fields["comment"] {
		t.Fatalf("fields mismatch: %v", got.Fields)
	}
}

func TestEncryptV3RejectsBadKind(t *testing.T) {
	priv, keyID := randomPixelKey(t)
	_, _, err := Encrypt(map[string]string{"a": "b"}, "bogus", "name", "id", keyID, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for unsupported kind")
	}
}

func TestNormalizeSecretName(t *testing.T) {
	good := []string{"api-keys/github", "ssh.gpg", "a", "x_y-z/9"}
	for _, g := range good {
		if _, err := NormalizeSecretName(g); err != nil {
			t.Fatalf("expected %q valid: %v", g, err)
		}
	}
	bad := []string{"", "Has-Caps", "a b", "https://x", "/lead", "trail/", "a//b", "a:b", ".lead", "-lead"}
	for _, b := range bad {
		if _, err := NormalizeSecretName(b); err == nil {
			t.Fatalf("expected %q invalid", b)
		}
	}
}

func TestNormalizeResource(t *testing.T) {
	if r, err := NormalizeResource(KindLogin, "https://example.com:443"); err != nil || r != "https://example.com" {
		t.Fatalf("login resource: %q %v", r, err)
	}
	if r, err := NormalizeResource(KindSecret, "API_KEYS/GitHub"); err == nil {
		t.Fatalf("expected uppercase name rejected, got %q", r)
	}
	if r, err := NormalizeResource(KindSecret, "api-keys/github"); err != nil || r != "api-keys/github" {
		t.Fatalf("secret resource: %q %v", r, err)
	}
	if _, err := NormalizeResource("bogus", "x"); err == nil {
		t.Fatal("expected error for bogus kind")
	}
}
