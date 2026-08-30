package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"vault-service/internal/crypto"
	"vault-service/internal/model"
)

var ErrNotFound = errors.New("credential not found")

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := applyMigrations(db); err != nil {
		return nil, err
	}
	return &DB{db: db}, nil
}

type DB struct {
	db *sql.DB
}

func (d *DB) Close() error {
	return d.db.Close()
}

func applyMigrations(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version >= 1 {
		return nil
	}

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS credentials (
			id TEXT PRIMARY KEY,
			origin TEXT NOT NULL UNIQUE,
			ciphertext BLOB NOT NULL,
			cipher_nonce BLOB NOT NULL,
			wrapped_dek BLOB NOT NULL,
			wrap_nonce BLOB NOT NULL,
			crypto_version INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	_, err = db.Exec("PRAGMA user_version = 1")
	return err
}

func (d *DB) CreateCredential(ctx context.Context, in model.CredentialInput, kek []byte) (model.Credential, error) {
	origin, err := model.NormalizeOrigin(in.Origin)
	if err != nil {
		return model.Credential{}, err
	}
	if in.Username == "" || in.Password == "" {
		return model.Credential{}, fmt.Errorf("username and password are required")
	}

	id, err := generateID()
	if err != nil {
		return model.Credential{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	payload, err := json.Marshal(map[string]string{
		"username": in.Username,
		"password": in.Password,
	})
	if err != nil {
		return model.Credential{}, err
	}

	rec, err := crypto.Encrypt(payload, id, origin, kek)
	if err != nil {
		return model.Credential{}, err
	}

	_, err = d.db.ExecContext(ctx, `
		INSERT INTO credentials
			(id, origin, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, crypto_version, created_at, updated_at)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, origin, rec.Ciphertext, rec.CipherNonce, rec.WrappedDEK, rec.WrapNonce, rec.CryptoVersion, now, now)
	if err != nil {
		return model.Credential{}, err
	}

	return d.getByOrigin(ctx, origin, kek)
}

func (d *DB) GetByOrigin(ctx context.Context, rawOrigin string, kek []byte) (model.Credential, error) {
	origin, err := model.NormalizeOrigin(rawOrigin)
	if err != nil {
		return model.Credential{}, err
	}
	return d.getByOrigin(ctx, origin, kek)
}

func (d *DB) getByOrigin(ctx context.Context, origin string, kek []byte) (model.Credential, error) {
	var id string
	var ciphertext, cipherNonce, wrappedDEK, wrapNonce []byte
	var cryptoVersion int
	var createdAt, updatedAt string

	err := d.db.QueryRowContext(ctx, `
		SELECT id, origin, ciphertext, cipher_nonce, wrapped_dek, wrap_nonce, crypto_version, created_at, updated_at
		FROM credentials
		WHERE origin = ?
	`, origin).Scan(&id, &origin, &ciphertext, &cipherNonce, &wrappedDEK, &wrapNonce, &cryptoVersion, &createdAt, &updatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Credential{}, ErrNotFound
		}
		return model.Credential{}, err
	}

	rec := &crypto.Record{
		Ciphertext:    ciphertext,
		CipherNonce:   cipherNonce,
		WrappedDEK:    wrappedDEK,
		WrapNonce:     wrapNonce,
		CryptoVersion: cryptoVersion,
	}
	plaintext, err := crypto.Decrypt(rec, id, origin, kek)
	if err != nil {
		return model.Credential{}, err
	}

	var payload map[string]string
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return model.Credential{}, err
	}

	return model.Credential{
		ID:        id,
		Origin:    origin,
		Username:  payload["username"],
		Password:  payload["password"],
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
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
		SELECT id, origin, created_at, updated_at
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
		if err := rows.Scan(&m.ID, &m.Origin, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) Update(ctx context.Context, id string, in model.CredentialInput, kek []byte) (model.Credential, error) {
	origin, err := model.NormalizeOrigin(in.Origin)
	if err != nil {
		return model.Credential{}, err
	}
	if in.Username == "" || in.Password == "" {
		return model.Credential{}, fmt.Errorf("username and password are required")
	}

	payload, err := json.Marshal(map[string]string{
		"username": in.Username,
		"password": in.Password,
	})
	if err != nil {
		return model.Credential{}, err
	}

	rec, err := crypto.Encrypt(payload, id, origin, kek)
	if err != nil {
		return model.Credential{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.db.ExecContext(ctx, `
		UPDATE credentials
		SET origin = ?, ciphertext = ?, cipher_nonce = ?,
		    wrapped_dek = ?, wrap_nonce = ?, crypto_version = ?, updated_at = ?
		WHERE id = ?
	`, origin, rec.Ciphertext, rec.CipherNonce, rec.WrappedDEK, rec.WrapNonce, rec.CryptoVersion, now, id)
	if err != nil {
		return model.Credential{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return model.Credential{}, err
	}
	if n == 0 {
		return model.Credential{}, ErrNotFound
	}

	return d.getByOrigin(ctx, origin, kek)
}

func (d *DB) Delete(ctx context.Context, id string) error {
	res, err := d.db.ExecContext(ctx, "DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { //nolint: staticcheck // crypto/rand is the intended package
		return "", err
	}
	return hex.EncodeToString(b), nil
}
