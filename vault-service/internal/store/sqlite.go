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
	ErrAmbiguous          = errors.New("multiple credentials match resource; specify kind or account")
	ErrApprovalReused     = errors.New("write approval has already been used")
	ErrIncompatibleSchema = errors.New("UA-VAULT-001: vault database schema is incompatible with this version; run 'authctl doctor' for repair instructions")
	currentSchemaVersion  = 4
	v2Columns             = []string{
		"id", "origin", "ciphertext", "cipher_nonce", "wrapped_dek",
		"wrap_nonce", "wrap_ephemeral_public_key", "pixel_vault_key_id",
		"crypto_version", "created_at", "updated_at",
	}
	v3Columns = []string{
		"id", "kind", "resource", "ciphertext", "cipher_nonce", "wrapped_dek",
		"wrap_nonce", "wrap_ephemeral_public_key", "pixel_vault_key_id",
		"crypto_version", "created_at", "updated_at",
	}
	requiredColumns = []string{
		"id", "kind", "resource", "account", "ciphertext", "cipher_nonce", "wrapped_dek",
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
	// SQLite is single-writer; one connection also keeps ":memory:" databases
	// from splitting across pooled connections.
	db.SetMaxOpenConns(1)
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

	ver, err := schemaVersion(db)
	if err != nil {
		return false, err
	}
	switch {
	case ver == currentSchemaVersion:
		if err := recordMigration(db, currentSchemaVersion); err != nil {
			return false, err
		}
		_, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion))
		return false, err
	case ver == 3:
		return migrateV3ToV4(db)
	case ver == 2:
		if incompat, err := migrateV2ToV3(db); err != nil || incompat {
			return incompat, err
		}
		return migrateV3ToV4(db)
	case ver > currentSchemaVersion:
		return true, nil
	default:
		// Early v2 databases recorded user_version 0 or 1; recognise them by
		// their columns so their credentials are migrated rather than refused.
		columns, err := getColumns(db, "credentials")
		if err != nil {
			return false, err
		}
		if hasAll(columns, v2Columns) && !columns["kind"] && !columns["resource"] {
			if incompat, err := migrateV2ToV3(db); err != nil || incompat {
				return incompat, err
			}
			return migrateV3ToV4(db)
		}
		return handleLegacy(db)
	}
}

// migrateV2ToV3 rebuilds the credentials table with kind/resource columns.
// Existing rows become kind='login' with resource=origin.
func migrateV2ToV3(db *sql.DB) (bool, error) {
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
	if !hasAll(columns, v2Columns) || columns["kind"] || columns["resource"] {
		return true, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	stmts := []string{
		`CREATE TABLE credentials_v3 (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			resource TEXT NOT NULL,
			ciphertext BLOB NOT NULL,
			cipher_nonce BLOB NOT NULL,
			wrapped_dek BLOB NOT NULL,
			wrap_nonce BLOB NOT NULL,
			wrap_ephemeral_public_key BLOB NOT NULL,
			pixel_vault_key_id TEXT NOT NULL,
			crypto_version INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(kind, resource)
		)`,
		`INSERT INTO credentials_v3
			(id, kind, resource, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at)
		SELECT id, 'login', origin, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at
		FROM credentials`,
		`DROP TABLE credentials`,
		`ALTER TABLE credentials_v3 RENAME TO credentials`,
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if err := recordMigration(db, 3); err != nil {
		return false, err
	}
	_, err = db.Exec("PRAGMA user_version = 3")
	return false, err
}

// migrateV3ToV4 adds the account label and widens uniqueness to
// (kind, resource, account) so a site can hold several accounts. Existing
// rows get an empty account.
func migrateV3ToV4(db *sql.DB) (bool, error) {
	columns, err := getColumns(db, "credentials")
	if err != nil {
		return false, err
	}
	if len(columns) == 0 {
		return createCurrentSchema(db)
	}
	if !columns["account"] {
		if !hasAll(columns, v3Columns) {
			return true, nil
		}
		tx, err := db.Begin()
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		stmts := []string{
			credentialsTableDDL("credentials_v4"),
			`INSERT INTO credentials_v4
				(id, kind, resource, account, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at)
			SELECT id, kind, resource, '', ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at
			FROM credentials`,
			`DROP TABLE credentials`,
			`ALTER TABLE credentials_v4 RENAME TO credentials`,
		}
		for _, st := range stmts {
			if _, err := tx.Exec(st); err != nil {
				return false, err
			}
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
	}
	if _, err := db.Exec(usedApprovalsDDL); err != nil {
		return false, err
	}
	if err := recordMigration(db, currentSchemaVersion); err != nil {
		return false, err
	}
	_, err = db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion))
	return false, err
}

func credentialsTableDDL(name string) string {
	return `CREATE TABLE IF NOT EXISTS ` + name + ` (
		id TEXT PRIMARY KEY,
		kind TEXT NOT NULL,
		resource TEXT NOT NULL,
		account TEXT NOT NULL DEFAULT '',
		ciphertext BLOB NOT NULL,
		cipher_nonce BLOB NOT NULL,
		wrapped_dek BLOB NOT NULL,
		wrap_nonce BLOB NOT NULL,
		wrap_ephemeral_public_key BLOB NOT NULL,
		pixel_vault_key_id TEXT NOT NULL,
		crypto_version INTEGER NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		UNIQUE(kind, resource, account)
	)`
}

// usedApprovalsDDL records consumed write approvals so each Pixel approval
// authorises exactly one write.
const usedApprovalsDDL = `CREATE TABLE IF NOT EXISTS used_approvals (
	request_id TEXT PRIMARY KEY,
	used_at TEXT NOT NULL
)`

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
	if hasAll(columns, v3Columns) && !columns["account"] {
		return migrateV3ToV4(db)
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
	if _, err := db.Exec(credentialsTableDDL("credentials")); err != nil {
		return false, err
	}
	if _, err := db.Exec(usedApprovalsDDL); err != nil {
		return false, err
	}
	if err := recordMigration(db, currentSchemaVersion); err != nil {
		return false, err
	}
	_, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion))
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
	max := 0
	for v := range applied {
		if v > max {
			max = v
		}
	}
	var pragma int
	if err := db.QueryRow("PRAGMA user_version").Scan(&pragma); err != nil {
		return 0, err
	}
	if pragma > max {
		return pragma, nil
	}
	return max, nil
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

// packageRow is the internal storage representation.
type packageRow struct {
	id                     string
	kind                   string
	resource               string
	account                string
	ciphertext             string
	cipherNonce            string
	wrappedDEK             string
	wrapNonce              string
	wrapEphemeralPublicKey string
	pixelVaultKeyID        string
	cryptoVersion          int
	createdAt              string
	updatedAt              string
}

func scanPackageRow(row interface{ Scan(...interface{}) error }) (*packageRow, error) {
	var r packageRow
	err := row.Scan(&r.id, &r.kind, &r.resource, &r.account, &r.ciphertext, &r.cipherNonce, &r.wrappedDEK,
		&r.wrapNonce, &r.wrapEphemeralPublicKey, &r.pixelVaultKeyID, &r.cryptoVersion,
		&r.createdAt, &r.updatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *packageRow) toPackage() model.CredentialPackage {
	pkg := model.CredentialPackage{
		CredentialID:           r.id,
		Ciphertext:             r.ciphertext,
		CipherNonce:            r.cipherNonce,
		WrappedDEK:             r.wrappedDEK,
		WrapNonce:              r.wrapNonce,
		WrapEphemeralPublicKey: r.wrapEphemeralPublicKey,
		PixelVaultKeyID:        r.pixelVaultKeyID,
		CryptoVersion:          r.cryptoVersion,
	}
	if r.cryptoVersion == 2 {
		pkg.Origin = r.resource
	} else {
		pkg.Kind = r.kind
		pkg.Resource = r.resource
	}
	pkg.Account = r.account
	return pkg
}

const packageColumns = `id, kind, resource, account, ciphertext, cipher_nonce, wrapped_dek,
	wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id,
	crypto_version, created_at, updated_at`

// validatedInput is a create/replace body after validation and normalisation.
type validatedInput struct {
	kind, resource, account string
}

func validateInput(in model.CredentialPackageInput) (validatedInput, error) {
	var v validatedInput
	if in.CryptoVersion != 2 && in.CryptoVersion != 3 {
		return v, fmt.Errorf("unsupported crypto version %d", in.CryptoVersion)
	}
	if in.CredentialID == "" {
		return v, fmt.Errorf("credential_id is required")
	}
	if _, err := hex.DecodeString(in.CredentialID); err != nil {
		return v, fmt.Errorf("credential_id must be lowercase hex")
	}
	var err error
	v.kind = model.KindLogin
	if in.CryptoVersion == 2 {
		if in.Origin == "" {
			return v, fmt.Errorf("origin is required")
		}
		v.resource, err = model.NormalizeOrigin(in.Origin)
	} else {
		if in.Kind != "" {
			v.kind = in.Kind
		}
		raw := in.Resource
		if raw == "" {
			raw = in.Origin // tolerate clients that still send origin
		}
		v.resource, err = model.NormalizeResource(v.kind, raw)
	}
	if err != nil {
		return v, err
	}
	v.account = strings.TrimSpace(in.Account)
	if len(v.account) > model.MaxAccountLen || strings.ContainsAny(v.account, "\r\n") {
		return v, fmt.Errorf("account must be a single line of at most %d bytes", model.MaxAccountLen)
	}
	if in.PixelVaultKeyID == "" {
		return v, fmt.Errorf("pixel_vault_key_id is required")
	}
	if in.WrapEphemeralPublicKey == "" {
		return v, fmt.Errorf("wrap_ephemeral_public_key is required")
	}
	if err := validateP256SPKI(in.WrapEphemeralPublicKey); err != nil {
		return v, fmt.Errorf("wrap_ephemeral_public_key: %w", err)
	}
	if in.Ciphertext == "" || in.CipherNonce == "" || in.WrappedDEK == "" || in.WrapNonce == "" {
		return v, fmt.Errorf("ciphertext, cipher_nonce, wrapped_dek and wrap_nonce are required")
	}
	if !isRawBase64url(in.Ciphertext) || !isRawBase64url(in.CipherNonce) || !isRawBase64url(in.WrappedDEK) || !isRawBase64url(in.WrapNonce) {
		return v, fmt.Errorf("binary fields must be unpadded Base64URL")
	}
	return v, nil
}

func (d *DB) CreateCredential(ctx context.Context, in model.CredentialPackageInput) (model.CredentialPackage, error) {
	v, err := validateInput(in)
	if err != nil {
		return model.CredentialPackage{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = d.db.ExecContext(ctx, `
		INSERT INTO credentials
			(id, kind, resource, account, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, wrap_ephemeral_public_key, pixel_vault_key_id, crypto_version, created_at, updated_at)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, in.CredentialID, v.kind, v.resource, v.account, in.Ciphertext, in.CipherNonce, in.WrappedDEK, in.WrapNonce, in.WrapEphemeralPublicKey, in.PixelVaultKeyID, in.CryptoVersion, now, now)
	if err != nil {
		if isConflict(err) {
			return model.CredentialPackage{}, fmt.Errorf("credential already exists for %s %s", v.kind, v.resource)
		}
		return model.CredentialPackage{}, err
	}
	return d.GetPackageByID(ctx, in.CredentialID)
}

// GetPackageByID fetches a package by credential ID.
func (d *DB) GetPackageByID(ctx context.Context, id string) (model.CredentialPackage, error) {
	row := d.db.QueryRowContext(ctx, `SELECT `+packageColumns+` FROM credentials WHERE id = ?`, id)
	r, err := scanPackageRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.CredentialPackage{}, ErrNotFound
	}
	if err != nil {
		return model.CredentialPackage{}, err
	}
	return r.toPackage(), nil
}

// GetPackageByResource fetches a package by resource. If kind is empty, any
// kind may match; multiple matches (kinds or accounts) return ErrAmbiguous.
func (d *DB) GetPackageByResource(ctx context.Context, rawResource, kind string) (model.CredentialPackage, error) {
	return d.GetPackage(ctx, rawResource, kind, nil)
}

// GetPackage fetches a package by resource, optionally restricted to kind and
// to an exact account label (nil means any account).
func (d *DB) GetPackage(ctx context.Context, rawResource, kind string, account *string) (model.CredentialPackage, error) {
	resource, err := normalizeLookupResource(rawResource, kind)
	if err != nil {
		return model.CredentialPackage{}, err
	}
	query := `SELECT ` + packageColumns + ` FROM credentials WHERE resource = ?`
	args := []interface{}{resource}
	if kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	if account != nil {
		query += ` AND account = ?`
		args = append(args, strings.TrimSpace(*account))
	}
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return model.CredentialPackage{}, err
	}
	defer rows.Close()
	var found *packageRow
	count := 0
	for rows.Next() {
		r, err := scanPackageRow(rows)
		if err != nil {
			return model.CredentialPackage{}, err
		}
		found = r
		count++
	}
	if err := rows.Err(); err != nil {
		return model.CredentialPackage{}, err
	}
	if count == 0 {
		return model.CredentialPackage{}, ErrNotFound
	}
	if count > 1 {
		return model.CredentialPackage{}, ErrAmbiguous
	}
	return found.toPackage(), nil
}

// normalizeLookupResource validates a lookup resource. Origins are normalized
// as login resources; other resources are accepted as secret names. When the
// caller supplies a kind, the matching rules apply.
func normalizeLookupResource(raw, kind string) (string, error) {
	if kind == model.KindLogin || kind == "" {
		if n, err := model.NormalizeOrigin(raw); err == nil {
			return n, nil
		}
	}
	if kind == "" || kind == model.KindSecret || kind == model.KindSSHKey {
		if n, err := model.NormalizeSecretName(raw); err == nil {
			return n, nil
		}
	}
	return "", fmt.Errorf("invalid resource %q", raw)
}

func (d *DB) Exists(ctx context.Context, rawResource, kind string) (bool, error) {
	resource, err := normalizeLookupResource(rawResource, kind)
	if err != nil {
		return false, err
	}
	query := `SELECT COUNT(*) FROM credentials WHERE resource = ?`
	args := []interface{}{resource}
	if kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	var n int
	err = d.db.QueryRowContext(ctx, query, args...).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// List returns metadata for all credentials.
func (d *DB) List(ctx context.Context) ([]model.CredentialMeta, error) {
	return d.ListFiltered(ctx, "", "")
}

// ListFiltered returns metadata, optionally restricted to a resource and kind.
func (d *DB) ListFiltered(ctx context.Context, rawResource, kind string) ([]model.CredentialMeta, error) {
	query := `SELECT id, kind, resource, account, pixel_vault_key_id, crypto_version, created_at, updated_at FROM credentials`
	var where []string
	var args []interface{}
	if rawResource != "" {
		resource, err := normalizeLookupResource(rawResource, kind)
		if err != nil {
			return nil, err
		}
		where = append(where, "resource = ?")
		args = append(args, resource)
	}
	if kind != "" {
		where = append(where, "kind = ?")
		args = append(args, kind)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY kind, resource, account"
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.CredentialMeta{}
	for rows.Next() {
		var m model.CredentialMeta
		if err := rows.Scan(&m.CredentialID, &m.Kind, &m.Resource, &m.Account, &m.PixelVaultKeyID, &m.CryptoVersion, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// consumeApproval records requestID inside tx; a second use fails.
func consumeApproval(ctx context.Context, tx *sql.Tx, requestID string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO used_approvals (request_id, used_at) VALUES (?, ?)`,
		requestID, time.Now().UTC().Format(time.RFC3339))
	if isConflict(err) {
		return ErrApprovalReused
	}
	return err
}

// Replace overwrites credential id with a new package, consuming the write
// approval identified by approvalID in the same transaction. The kind cannot
// change; resource and account may.
func (d *DB) Replace(ctx context.Context, id string, in model.CredentialPackageInput, approvalID string) (model.CredentialPackage, error) {
	if in.CredentialID != id {
		return model.CredentialPackage{}, fmt.Errorf("credential_id must match the credential being replaced")
	}
	if in.CryptoVersion != 3 {
		return model.CredentialPackage{}, fmt.Errorf("replacement packages must be crypto version 3")
	}
	v, err := validateInput(in)
	if err != nil {
		return model.CredentialPackage{}, err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return model.CredentialPackage{}, err
	}
	defer tx.Rollback()
	var curKind string
	if err := tx.QueryRowContext(ctx, `SELECT kind FROM credentials WHERE id = ?`, id).Scan(&curKind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.CredentialPackage{}, ErrNotFound
		}
		return model.CredentialPackage{}, err
	}
	if curKind != v.kind {
		return model.CredentialPackage{}, fmt.Errorf("kind cannot change from %s to %s", curKind, v.kind)
	}
	if err := consumeApproval(ctx, tx, approvalID); err != nil {
		return model.CredentialPackage{}, err
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE credentials SET resource = ?, account = ?, ciphertext = ?, cipher_nonce = ?, wrapped_dek = ?,
			wrap_nonce = ?, wrap_ephemeral_public_key = ?, pixel_vault_key_id = ?, crypto_version = ?, updated_at = ?
		WHERE id = ?
	`, v.resource, v.account, in.Ciphertext, in.CipherNonce, in.WrappedDEK, in.WrapNonce,
		in.WrapEphemeralPublicKey, in.PixelVaultKeyID, in.CryptoVersion, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		if isConflict(err) {
			return model.CredentialPackage{}, fmt.Errorf("credential already exists for %s %s", v.kind, v.resource)
		}
		return model.CredentialPackage{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.CredentialPackage{}, err
	}
	return d.GetPackageByID(ctx, id)
}

// Delete removes credential id, consuming the write approval approvalID.
func (d *DB) Delete(ctx context.Context, id, approvalID string) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := consumeApproval(ctx, tx, approvalID); err != nil {
		return err
	}
	return tx.Commit()
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
