package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "desktop-identity.pem")
	id, err := LoadOrCreate(p)
	if err != nil {
		t.Fatalf("load or create: %v", err)
	}
	if id.DesktopID() == "" {
		t.Fatal("desktop id is empty")
	}
	if id.PublicKey() == "" {
		t.Fatal("public key is empty")
	}

	// Verify fingerprint matches public key.
	der, err := base64.StdEncoding.DecodeString(id.PublicKey())
	if err != nil {
		t.Fatalf("public key decode: %v", err)
	}
	sum := sha256.Sum256(der)
	want := hex.EncodeToString(sum[:])
	if id.DesktopID() != want {
		t.Fatalf("desktop id mismatch: got %s want %s", id.DesktopID(), want)
	}

	// Verify parse.
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	_ = pubAny

	// Sign/verify.
	msg := []byte("hello")
	digest := sha256.Sum256(msg)
	sig, err := id.Sign(digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := id.Verify(digest[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Re-load.
	id2, err := LoadOrCreate(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if id2.DesktopID() != id.DesktopID() {
		t.Fatal("reload changed identity")
	}

	// Permission check (file is 0600 or 0644 on some filesystems; at a minimum not world-readable).
	st, _ := os.Stat(p)
	if st != nil && st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("permissions too permissive: %o", st.Mode().Perm())
	}
}

func TestIdentityModifiedSignatureFails(t *testing.T) {
	dir := t.TempDir()
	id, _ := LoadOrCreate(filepath.Join(dir, "id.pem"))
	digest := sha256.Sum256([]byte("hello"))
	digest2 := sha256.Sum256([]byte("other"))
	sig, _ := id.Sign(digest[:])
	if err := id.Verify(digest2[:], sig); err == nil {
		t.Fatal("expected verification to fail for different digest")
	}
}
