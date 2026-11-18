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
	"fmt"
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

	got, err := db.GetPackageByResource(context.Background(), "https://github.com", "")
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

	exists, err := db.Exists(context.Background(), "https://github.com", "")
	if err != nil || !exists {
		t.Fatalf("expected exists, got %v / %v", exists, err)
	}
	exists, _ = db.Exists(context.Background(), "https://other.com", "")
	if exists {
		t.Fatal("did not expect other origin to exist")
	}

	list, err := db.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v", err)
	}
	if list[0].Resource != "https://github.com" || list[0].Kind != model.KindLogin || list[0].CryptoVersion != 2 {
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

	if err := db.Delete(context.Background(), c.CredentialID, "approval-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := db.GetPackageByResource(context.Background(), "https://github.com", "")
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

func newPackageV3(t *testing.T, kind, resource string) model.CredentialPackageInput {
	t.Helper()
	return model.CredentialPackageInput{
		CredentialID:           randomHex(t, 16),
		Kind:                   kind,
		Resource:               resource,
		Ciphertext:             randomB64(t, 48),
		CipherNonce:            randomB64(t, 12),
		WrappedDEK:             randomB64(t, 48),
		WrapNonce:              randomB64(t, 12),
		WrapEphemeralPublicKey: randomP256SPKI(t),
		PixelVaultKeyID:        randomHex(t, 32),
		CryptoVersion:          3,
	}
}

func TestCreateV3SecretAndSSHKey(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	sec := newPackageV3(t, model.KindSecret, "api-keys/github")
	c, err := db.CreateCredential(context.Background(), sec)
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if c.Kind != model.KindSecret || c.Resource != "api-keys/github" {
		t.Fatalf("got %+v", c)
	}

	ssh := newPackageV3(t, model.KindSSHKey, "ssh/gmail")
	if _, err := db.CreateCredential(context.Background(), ssh); err != nil {
		t.Fatalf("create ssh_key: %v", err)
	}

	got, err := db.GetPackageByResource(context.Background(), "api-keys/github", "")
	if err != nil || got.CredentialID != sec.CredentialID {
		t.Fatalf("get secret: %v / %+v", err, got)
	}

	// Same resource name under a different kind is allowed.
	dup := newPackageV3(t, model.KindSSHKey, "api-keys/github")
	if _, err := db.CreateCredential(context.Background(), dup); err != nil {
		t.Fatalf("same name different kind should be allowed: %v", err)
	}

	// Without a kind, the resource is ambiguous.
	_, err = db.GetPackageByResource(context.Background(), "api-keys/github", "")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}
	got, err = db.GetPackageByResource(context.Background(), "api-keys/github", model.KindSSHKey)
	if err != nil || got.CredentialID != dup.CredentialID {
		t.Fatalf("get by kind: %v / %+v", err, got)
	}
}

func TestV3RejectsBadResource(t *testing.T) {
	db := tempDB(t)
	defer db.Close()

	bad := newPackageV3(t, model.KindSecret, "Not Valid!!")
	if _, err := db.CreateCredential(context.Background(), bad); err == nil {
		t.Fatal("expected invalid resource error")
	}
	badKind := newPackageV3(t, "bogus", "name")
	if _, err := db.CreateCredential(context.Background(), badKind); err == nil {
		t.Fatal("expected invalid kind error")
	}
}

func TestMigrateV2ToV3(t *testing.T) {
	t.Run("tracked", func(t *testing.T) { testMigrateV2ToV3(t, true, 2) })
	t.Run("untracked user_version 2", func(t *testing.T) { testMigrateV2ToV3(t, false, 2) })
	t.Run("untracked user_version 1", func(t *testing.T) { testMigrateV2ToV3(t, false, 1) })
}

func testMigrateV2ToV3(t *testing.T, tracked bool, userVersion int) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	// One connection, so every statement sees the same in-memory database.
	db.SetMaxOpenConns(1)

	// Build a v2-shaped database.
	if tracked {
		if _, err := db.Exec(`
			CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
			INSERT INTO schema_migrations (version, applied_at) VALUES (2, '2026-01-01T00:00:00Z');
		`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", userVersion)); err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			origin TEXT NOT NULL UNIQUE,
			ciphertext BLOB NOT NULL,
			cipher_nonce BLOB NOT NULL,
			wrapped_dek BLOB NOT NULL,
			wrap_nonce BLOB NOT NULL,
			wrap_ephemeral_public_key BLOB NOT NULL,
			pixel_vault_key_id TEXT NOT NULL,
			crypto_version INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		INSERT INTO credentials (id, origin, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at)
		VALUES ('abc123', 'https://github.com', 'Y2lwaGVy', 'bm9uY2U', 'ZGVr', 'd3JhcA', 'a2V5', 'pix', 2, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
	`)
	incompat, err := applyMigrations(db)
	if err != nil || incompat {
		t.Fatalf("applyMigrations: %v / %v", incompat, err)
	}

	store := &DB{db: db}
	if err := store.Ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}

	pkg, err := store.GetPackageByResource(context.Background(), "https://github.com", "")
	if err != nil {
		t.Fatalf("get migrated: %v", err)
	}
	if pkg.CredentialID != "abc123" || pkg.Origin != "https://github.com" || pkg.CryptoVersion != 2 {
		t.Fatalf("unexpected migrated package: %+v", pkg)
	}

	// New v3 insert works after migration.
	sec := newPackageV3(t, model.KindSecret, "api-keys/github")
	if _, err := store.CreateCredential(context.Background(), sec); err != nil {
		t.Fatalf("create after migration: %v", err)
	}
}

func TestMultipleAccountsPerSite(t *testing.T) {
	db := tempDB(t)
	defer db.Close()
	ctx := context.Background()

	personal := newPackageV3(t, model.KindLogin, "https://accounts.google.com")
	personal.Account = "me@gmail.com"
	work := newPackageV3(t, model.KindLogin, "https://accounts.google.com")
	work.Account = "me@work.com"
	if _, err := db.CreateCredential(ctx, personal); err != nil {
		t.Fatalf("create personal: %v", err)
	}
	if _, err := db.CreateCredential(ctx, work); err != nil {
		t.Fatalf("create work: %v", err)
	}
	dup := newPackageV3(t, model.KindLogin, "https://accounts.google.com")
	dup.Account = "me@work.com"
	if _, err := db.CreateCredential(ctx, dup); err == nil {
		t.Fatal("same site + account must conflict")
	}

	list, err := db.ListFiltered(ctx, "https://accounts.google.com", model.KindLogin)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v / %d", err, len(list))
	}
	if list[0].Account != "me@gmail.com" || list[1].Account != "me@work.com" {
		t.Fatalf("accounts: %+v", list)
	}
	if _, err := db.GetPackageByResource(ctx, "https://accounts.google.com", model.KindLogin); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}
	acct := "me@work.com"
	got, err := db.GetPackage(ctx, "https://accounts.google.com", model.KindLogin, &acct)
	if err != nil || got.CredentialID != work.CredentialID || got.Account != acct {
		t.Fatalf("get by account: %v / %+v", err, got)
	}
	byID, err := db.GetPackageByID(ctx, personal.CredentialID)
	if err != nil || byID.Account != "me@gmail.com" {
		t.Fatalf("get by id: %v / %+v", err, byID)
	}
	if _, err := db.GetPackageByID(ctx, "deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id: %v", err)
	}
	bad := newPackageV3(t, model.KindLogin, "https://x.com")
	bad.Account = "two\nlines"
	if _, err := db.CreateCredential(ctx, bad); err == nil {
		t.Fatal("multi-line account must be rejected")
	}
}

func TestReplaceAndDeleteConsumeApproval(t *testing.T) {
	db := tempDB(t)
	defer db.Close()
	ctx := context.Background()

	orig := newPackageV3(t, model.KindLogin, "https://utexas.edu")
	orig.Account = "ajl"
	if _, err := db.CreateCredential(ctx, orig); err != nil {
		t.Fatal(err)
	}
	upd := newPackageV3(t, model.KindLogin, "https://enterprise.login.utexas.edu")
	upd.CredentialID = orig.CredentialID
	upd.Account = "ajl5646"
	got, err := db.Replace(ctx, orig.CredentialID, upd, "req-1")
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got.Resource != "https://enterprise.login.utexas.edu" || got.Account != "ajl5646" || got.Ciphertext != upd.Ciphertext {
		t.Fatalf("replaced: %+v", got)
	}
	if _, err := db.Replace(ctx, orig.CredentialID, upd, "req-1"); !errors.Is(err, ErrApprovalReused) {
		t.Fatalf("reused approval: %v", err)
	}
	kindChange := upd
	kindChange.Kind = model.KindSecret
	kindChange.Resource = "x/y"
	if _, err := db.Replace(ctx, orig.CredentialID, kindChange, "req-2"); err == nil {
		t.Fatal("kind change must be rejected")
	}
	otherID := upd
	otherID.CredentialID = randomHex(t, 16)
	if _, err := db.Replace(ctx, orig.CredentialID, otherID, "req-3"); err == nil {
		t.Fatal("mismatched credential_id must be rejected")
	}
	if err := db.Delete(ctx, orig.CredentialID, "req-1"); !errors.Is(err, ErrApprovalReused) {
		t.Fatalf("delete with used approval: %v", err)
	}
	if _, err := db.GetPackageByID(ctx, orig.CredentialID); err != nil {
		t.Fatalf("failed delete must leave the credential: %v", err)
	}
	if err := db.Delete(ctx, orig.CredentialID, "req-4"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestMigrateV3ToV4(t *testing.T) {
	raw, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(`
		CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
		INSERT INTO schema_migrations (version, applied_at) VALUES (3, '2026-01-01T00:00:00Z');
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY, kind TEXT NOT NULL, resource TEXT NOT NULL,
			ciphertext BLOB NOT NULL, cipher_nonce BLOB NOT NULL, wrapped_dek BLOB NOT NULL,
			wrap_nonce BLOB NOT NULL, wrap_ephemeral_public_key BLOB NOT NULL,
			pixel_vault_key_id TEXT NOT NULL, crypto_version INTEGER NOT NULL,
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(kind, resource));
		INSERT INTO credentials VALUES ('abc123','login','https://github.com','Y2lwaGVy','bm9uY2U','ZGVr','d3JhcA','a2V5','pix',3,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');
		PRAGMA user_version = 3;
	`); err != nil {
		t.Fatal(err)
	}
	if incompat, err := applyMigrations(raw); err != nil || incompat {
		t.Fatalf("migrate: %v / %v", incompat, err)
	}
	db := &DB{db: raw}
	if err := db.Ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}
	got, err := db.GetPackageByID(context.Background(), "abc123")
	if err != nil || got.Resource != "https://github.com" || got.Account != "" {
		t.Fatalf("migrated row: %v / %+v", err, got)
	}
	second := newPackageV3(t, model.KindLogin, "https://github.com")
	second.Account = "work"
	if _, err := db.CreateCredential(context.Background(), second); err != nil {
		t.Fatalf("second account after migration: %v", err)
	}
}
