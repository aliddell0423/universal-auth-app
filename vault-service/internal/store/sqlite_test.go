package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	_ "modernc.org/sqlite"

	"vault-service/internal/model"
)

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func randomB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomP256SPKI(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return base64.RawURLEncoding.EncodeToString(der)
}

func tempDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

func newPackage(t *testing.T, origin string) model.CredentialPackageInput {
	t.Helper()
	return model.CredentialPackageInput{
		CredentialID:           randomHex(t, 16),
		Origin:                 origin,
		Ciphertext:             randomB64(t, 48),
		CipherNonce:            randomB64(t, 12),
		WrappedDEK:             randomB64(t, 48),
		WrapNonce:              randomB64(t, 12),
		WrapEphemeralPublicKey: randomP256SPKI(t),
		PixelVaultKeyID:        randomHex(t, 32),
		CryptoVersion:          2,
	}
}

func TestCreateAndGetPackage(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	in := newPackage(t, "https://github.com")
	c, err := db.CreateCredential(context.Background(), in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.CredentialID != in.CredentialID {
		t.Fatalf("got %s", c.CredentialID)
	}

	got, err := db.GetPackageByOrigin(context.Background(), "https://github.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CredentialID != in.CredentialID || got.Origin != "https://github.com" {
		t.Fatalf("got %v", got)
	}
}

func TestExistsAndList(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	in := newPackage(t, "https://github.com")
	_, _ = db.CreateCredential(context.Background(), in)

	exists, err := db.Exists(context.Background(), "https://github.com")
	if err != nil || !exists {
		t.Fatalf("expected exists, got %v / %v", exists, err)
	}
	exists, _ = db.Exists(context.Background(), "https://other.com")
	if exists {
		t.Fatal("did not expect other origin to exist")
	}

	list, err := db.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v", err)
	}
	if list[0].Origin != "https://github.com" || list[0].CryptoVersion != 2 {
		t.Fatalf("got %v", list[0])
	}
}

func TestDuplicateOrigin(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	in := newPackage(t, "https://github.com")
	_, _ = db.CreateCredential(context.Background(), in)
	_, err := db.CreateCredential(context.Background(), in)
	if err == nil {
		t.Fatal("expected duplicate origin error")
	}
}

func TestDelete(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	in := newPackage(t, "https://github.com")
	c, _ := db.CreateCredential(context.Background(), in)

	if err := db.Delete(context.Background(), c.CredentialID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := db.GetPackageByOrigin(context.Background(), "https://github.com")
	if !isNotFound(err) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestLegacyCryptoVersion(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	in := newPackage(t, "https://github.com")
	in.CryptoVersion = 1
	_, err := db.CreateCredential(context.Background(), in)
	if err == nil {
		t.Fatal("expected unsupported crypto version")
	}
}

func isNotFound(err error) bool {
	return err == ErrNotFound
}

func TestReadyAfterCreate(t *testing.T) {
	db := tempDB(t)
	defer db.Close()
	if err := db.Ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}
}

func TestIncompatibleLegacyDB(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = db.Exec(`
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			origin TEXT NOT NULL UNIQUE,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
	`)
	_, _ = db.Exec(`
		INSERT INTO credentials (id, origin, username, password, created_at)
		VALUES ('1', 'https://github.com', 'user', 'pass', '2026-01-01T00:00:00Z');
	`)

	store := &DB{db: db}
	if err := store.Ready(); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("expected ErrIncompatibleSchema, got %v", err)
	}

	// Verify data was not dropped.
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&n); err != nil || n != 1 {
		t.Fatalf("legacy data not preserved: %v / %d", err, n)
	}
	db.Close()
}

func TestEmptyLegacyDBUpgraded(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = db.Exec(`
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			origin TEXT NOT NULL UNIQUE,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
	`)

	incompat, err := applyMigrations(db)
	if err != nil || incompat {
		t.Fatalf("applyMigrations: %v / %v", incompat, err)
	}

	store := &DB{db: db}
	if err := store.Ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version not set: %v / %d", err, version)
	}
	db.Close()
}
