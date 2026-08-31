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
	currentSchemaVersion  = 1
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
	return validateSchema(d.db)
}

func applyMigrations(db *sql.DB) (bool, error) {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return false, err
	}
	if version >= currentSchemaVersion {
		return false, nil
	}

	var n int
	err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='credentials'").Scan(&n)
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, createSchema(db)
	}

	columns, err := getColumns(db, "credentials")
	if err != nil {
		return false, err
	}
	if hasAll(columns, requiredColumns) {
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
		return false, createSchema(db)
	}

	// Non-empty legacy database that cannot be safely migrated. Leave it untouched.
	return true, nil
}

func createSchema(db *sql.DB) error {
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
		return err
	}
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion))
	return err
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
