package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kek := randomBytes(t, 32)
	plaintext := []byte(`{"username":"u","password":"p"}`)
	rec, err := Encrypt(plaintext, "id1", "https://example.com", kek)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := Decrypt(rec, "id1", "https://example.com", kek)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestDecryptWrongKEK(t *testing.T) {
	kek := randomBytes(t, 32)
	wrong := randomBytes(t, 32)
	plaintext := []byte(`secret`)
	rec, err := Encrypt(plaintext, "id", "https://example.com", kek)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = Decrypt(rec, "id", "https://example.com", wrong)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong KEK")
	}
}

func TestDecryptModifiedCiphertext(t *testing.T) {
	kek := randomBytes(t, 32)
	rec, _ := Encrypt([]byte(`secret`), "id", "https://example.com", kek)
	rec.Ciphertext[0] ^= 0xff
	_, err := Decrypt(rec, "id", "https://example.com", kek)
	if err == nil {
		t.Fatal("expected auth failure for modified ciphertext")
	}
}

func TestDecryptModifiedCipherNonce(t *testing.T) {
	kek := randomBytes(t, 32)
	rec, _ := Encrypt([]byte(`secret`), "id", "https://example.com", kek)
	rec.CipherNonce[0] ^= 0xff
	_, err := Decrypt(rec, "id", "https://example.com", kek)
	if err == nil {
		t.Fatal("expected auth failure for modified cipher nonce")
	}
}

func TestDecryptModifiedWrapNonce(t *testing.T) {
	kek := randomBytes(t, 32)
	rec, _ := Encrypt([]byte(`secret`), "id", "https://example.com", kek)
	rec.WrapNonce[0] ^= 0xff
	_, err := Decrypt(rec, "id", "https://example.com", kek)
	if err == nil {
		t.Fatal("expected unwrap to fail for modified wrap nonce")
	}
}

func TestDecryptModifiedAAD(t *testing.T) {
	kek := randomBytes(t, 32)
	rec, _ := Encrypt([]byte(`secret`), "id", "https://example.com", kek)
	_, err := Decrypt(rec, "id", "https://other.com", kek)
	if err == nil {
		t.Fatal("expected auth failure for mismatched AAD/origin")
	}
}

func TestEncryptionProducesDifferentCiphertexts(t *testing.T) {
	kek := randomBytes(t, 32)
	plaintext := []byte(`same`)
	a, _ := Encrypt(plaintext, "id", "https://example.com", kek)
	b, _ := Encrypt(plaintext, "id", "https://example.com", kek)
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("ciphertexts should be different")
	}
	if bytes.Equal(a.CipherNonce, b.CipherNonce) {
		t.Fatal("cipher nonces should be different")
	}
	if bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("wrapped DEKs should be different")
	}
	if bytes.Equal(a.WrapNonce, b.WrapNonce) {
		t.Fatal("wrap nonces should be different")
	}
}
