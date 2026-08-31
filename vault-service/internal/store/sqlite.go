package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"vault-service/internal/model"
)

var (
	ErrNotFound           = errors.New("credential not found")
	ErrIncompatibleSchema = errors.New("UA-VAULT-001: vault database schema is incompatible with this version; run 'authctl doctor' for repair instructions")
	currentSchemaVersion  = 2
	requiredColumns       = []string{
		"id", "origin", "ciphertext", "cipher_nonce", "wrapped_dek",
		"wrap_nonce", "wrap_ephemeral_public_key", "pixel_vault_key_id",
		"crypto_version", "created_at", "updated_at",
	}
)

type DB struct {
	db           *sql.DB
	incompatible bool
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	incompatible, err := applyMigrations(db)
	if err != nil {
		return nil, err
	}
	return &DB{db: db, incompatible: incompatible}, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

// Ready reports whether the database is currently usable by this version.
func (d *DB) Ready() error {
	if d.incompatible {
		return ErrIncompatibleSchema
	}
	if err := d.db.Ping(); err != nil {
		return err
	}
	v, err := schemaVersion(d.db)
	if err != nil {
		return err
	}
	if v != currentSchemaVersion {
		return ErrIncompatibleSchema
	}
	return validateSchema(d.db)
}

func applyMigrations(db *sql.DB) (bool, error) {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return false, err
	}

	applied, err := appliedVersions(db)
	if err != nil {
		return false, err
	}
	if applied[currentSchemaVersion] {
		return false, nil
	}

	// No schema_migrations record for version 2. Fall back to PRAGMA user_version.
	var userVer int
	if err := db.QueryRow("PRAGMA user_version").Scan(&userVer); err != nil {
		return false, err
	}
	if userVer == currentSchemaVersion {
		// Database already current but not tracked; record it.
		if err := recordMigration(db, currentSchemaVersion); err != nil {
			return false, err
		}
		return false, nil
	}
	if userVer > currentSchemaVersion {
		return true, nil
	}
	if userVer == 1 {
		// Old-style v2 storage that set PRAGMA user_version to 1. Verify the
		// table has the expected columns; if so, it is the current schema.
		columns, err := getColumns(db, "credentials")
		if err != nil {
			return false, err
		}
		if hasAll(columns, requiredColumns) {
			if err := recordMigration(db, currentSchemaVersion); err != nil {
				return false, err
			}
			_, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion))
			return false, err
		}
		return handleLegacy(db)
	}
	// userVer == 0 or unknown: legacy or fresh database.
	return handleLegacy(db)
}

func handleLegacy(db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='credentials'").Scan(&n)
	if err != nil {
		return false, err
	}
	if n == 0 {
		return createCurrentSchema(db)
	}

	columns, err := getColumns(db, "credentials")
	if err != nil {
		return false, err
	}
	if hasAll(columns, requiredColumns) {
		// Table already current; just record it.
		if err := recordMigration(db, currentSchemaVersion); err != nil {
			return false, err
		}
		_, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion))
		return false, err
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&count); err != nil {
		return false, err
	}
	if count == 0 {
		if _, err := db.Exec("DROP TABLE credentials"); err != nil {
			return false, err
		}
		return createCurrentSchema(db)
	}

	// Non-empty legacy database that cannot be safely migrated.
	return true, nil
}

func createCurrentSchema(db *sql.DB) (bool, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS credentials (
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
	`)
	if err != nil {
		return false, err
	}
	if err := recordMigration(db, currentSchemaVersion); err != nil {
		return false, err
	}
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion))
	return false, err
}

func recordMigration(db *sql.DB, version int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec("INSERT OR REPLACE INTO schema_migrations (version, applied_at) VALUES (?, ?)", version, now)
	return err
}

func appliedVersions(db *sql.DB) (map[int]bool, error) {
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func schemaVersion(db *sql.DB) (int, error) {
	applied, err := appliedVersions(db)
	if err != nil {
		return 0, err
	}
	if len(applied) > 0 {
		max := 0
		for v := range applied {
			if v > max {
				max = v
			}
		}
		return max, nil
	}
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

func validateSchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != currentSchemaVersion {
		return ErrIncompatibleSchema
	}
	columns, err := getColumns(db, "credentials")
	if err != nil {
		return err
	}
	if !hasAll(columns, requiredColumns) {
		return ErrIncompatibleSchema
	}
	return nil
}

func getColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

func hasAll(have map[string]bool, want []string) bool {
	for _, c := range want {
		if !have[c] {
			return false
		}
	}
	return true
}

func (d *DB) CreateCredential(ctx context.Context, in model.CredentialPackageInput) (model.CredentialPackage, error) {
	if in.CryptoVersion != 2 {
		return model.CredentialPackage{}, fmt.Errorf("unsupported crypto version %d", in.CryptoVersion)
	}
	if in.CredentialID == "" {
		return model.CredentialPackage{}, fmt.Errorf("credential_id is required")
	}
	if _, err := hex.DecodeString(in.CredentialID); err != nil {
		return model.CredentialPackage{}, fmt.Errorf("credential_id must be lowercase hex")
	}
	if in.Origin == "" {
		return model.CredentialPackage{}, fmt.Errorf("origin is required")
	}
	origin, err := model.NormalizeOrigin(in.Origin)
	if err != nil {
		return model.CredentialPackage{}, err
	}
	if in.PixelVaultKeyID == "" {
		return model.CredentialPackage{}, fmt.Errorf("pixel_vault_key_id is required")
	}
	if in.WrapEphemeralPublicKey == "" {
		return model.CredentialPackage{}, fmt.Errorf("wrap_ephemeral_public_key is required")
	}
	if err := validateP256SPKI(in.WrapEphemeralPublicKey); err != nil {
		return model.CredentialPackage{}, fmt.Errorf("wrap_ephemeral_public_key: %w", err)
	}
	if in.Ciphertext == "" || in.CipherNonce == "" || in.WrappedDEK == "" || in.WrapNonce == "" {
		return model.CredentialPackage{}, fmt.Errorf("ciphertext, cipher_nonce, wrapped_dek and wrap_nonce are required")
	}
	if !isRawBase64url(in.Ciphertext) || !isRawBase64url(in.CipherNonce) || !isRawBase64url(in.WrappedDEK) || !isRawBase64url(in.WrapNonce) {
		return model.CredentialPackage{}, fmt.Errorf("binary fields must be unpadded Base64URL")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = d.db.ExecContext(ctx, `
		INSERT INTO credentials
			(id, origin, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, in.CredentialID, origin, in.Ciphertext, in.CipherNonce, in.WrappedDEK, in.WrapNonce, in.WrapEphemeralPublicKey, in.PixelVaultKeyID, in.CryptoVersion, now, now)
	if err != nil {
		if isConflict(err) {
			return model.CredentialPackage{}, fmt.Errorf("credential already exists for origin")
		}
		return model.CredentialPackage{}, err
	}
	return d.getByOrigin(ctx, origin)
}

func (d *DB) GetPackageByOrigin(ctx context.Context, rawOrigin string) (model.CredentialPackage, error) {
	origin, err := model.NormalizeOrigin(rawOrigin)
	if err != nil {
		return model.CredentialPackage{}, err
	}
	return d.getByOrigin(ctx, origin)
}

func (d *DB) getByOrigin(ctx context.Context, origin string) (model.CredentialPackage, error) {
	var pkg model.CredentialPackage
	var created, updated string
	err := d.db.QueryRowContext(ctx, `
		SELECT id, origin, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at
		FROM credentials
		WHERE origin = ?
	`, origin).Scan(&pkg.CredentialID, &pkg.Origin, &pkg.Ciphertext, &pkg.CipherNonce, &pkg.WrappedDEK, &pkg.WrapNonce, &pkg.WrapEphemeralPublicKey, &pkg.PixelVaultKeyID, &pkg.CryptoVersion, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.CredentialPackage{}, ErrNotFound
		}
		return model.CredentialPackage{}, err
	}
	return pkg, nil
}

func (d *DB) Exists(ctx context.Context, rawOrigin string) (bool, error) {
	origin, err := model.NormalizeOrigin(rawOrigin)
	if err != nil {
		return false, err
	}
	var n int
	err = d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM credentials WHERE origin = ?", origin).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (d *DB) List(ctx context.Context) ([]model.CredentialMeta, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT id, origin, pixel_vault_key_id, crypto_version, created_at, updated_at
		FROM credentials
		ORDER BY origin
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.CredentialMeta
	for rows.Next() {
		var m model.CredentialMeta
		if err := rows.Scan(&m.CredentialID, &m.Origin, &m.PixelVaultKeyID, &m.CryptoVersion, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) Delete(ctx context.Context, id string) error {
	res, err := d.db.ExecContext(ctx, "DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func validateP256SPKI(b64 string) error {
	der, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		der, err = base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("not valid base64")
		}
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("not valid SPKI")
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return fmt.Errorf("not a P-256 ECDSA key")
	}
	return nil
}

func isRawBase64url(s string) bool {
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

func isConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
