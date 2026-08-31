package persist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrCorruptDevice  = errors.New("persisted trusted device is corrupt or inconsistent")
	ErrCorruptDesktop = errors.New("persisted trusted desktop is corrupt or inconsistent")
	currentVersion    = 1
)

type TrustedDevice struct {
	DeviceID       string
	Name           string
	Algorithm      string
	PublicKey      []byte
	VaultKeyID     string
	VaultAlgo      string
	VaultPublicKey []byte
	CreatedAt      string
	UpdatedAt      string
}

type TrustedDesktop struct {
	DesktopID string
	Name      string
	Algorithm string
	PublicKey []byte
	CreatedAt string
	UpdatedAt string
}

type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	if path == "" {
		path = ":memory:"
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	return &DB{db: db}, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) Ready() error {
	var v int
	err := d.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&v)
	if err != nil {
		return err
	}
	if v != currentVersion {
		return fmt.Errorf("broker schema not ready")
	}
	return nil
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return err
	}

	var v int
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&v); err != nil {
		return err
	}
	if v == currentVersion {
		return nil
	}
	if v > currentVersion {
		return fmt.Errorf("broker schema version %d is newer than supported %d", v, currentVersion)
	}

	// Fresh or legacy in-memory only database.
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS trusted_device (
			device_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			public_key_der BLOB NOT NULL,
			vault_key_id TEXT NOT NULL,
			vault_algorithm TEXT NOT NULL,
			vault_public_key_der BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS trusted_desktop (
			desktop_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			public_key_der BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec("INSERT OR REPLACE INTO schema_migrations (version, applied_at) VALUES (?, ?)", currentVersion, now)
	return err
}

func (d *DB) LoadDevice() (*TrustedDevice, error) {
	var td TrustedDevice
	var err error
	err = d.db.QueryRow(`
		SELECT device_id, name, algorithm, public_key_der, vault_key_id, vault_algorithm, vault_public_key_der, created_at, updated_at
		FROM trusted_device
		LIMIT 1
	`).Scan(&td.DeviceID, &td.Name, &td.Algorithm, &td.PublicKey, &td.VaultKeyID, &td.VaultAlgo, &td.VaultPublicKey, &td.CreatedAt, &td.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := validateDevice(td); err != nil {
		return nil, err
	}
	return &td, nil
}

func (d *DB) LoadDesktop() (*TrustedDesktop, error) {
	var td TrustedDesktop
	err := d.db.QueryRow(`
		SELECT desktop_id, name, algorithm, public_key_der, created_at, updated_at
		FROM trusted_desktop
		LIMIT 1
	`).Scan(&td.DesktopID, &td.Name, &td.Algorithm, &td.PublicKey, &td.CreatedAt, &td.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if err := validateDesktop(td); err != nil {
		return nil, err
	}
	return &td, nil
}

func validateDevice(td TrustedDevice) error {
	pub, err := parseP256(td.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: public key: %v", ErrCorruptDevice, err)
	}
	if deviceID(pub) != td.DeviceID {
		return fmt.Errorf("%w: device_id does not match public key", ErrCorruptDevice)
	}
	vaultPub, err := parseP256(td.VaultPublicKey)
	if err != nil {
		return fmt.Errorf("%w: vault public key: %v", ErrCorruptDevice, err)
	}
	if deviceID(vaultPub) != td.VaultKeyID {
		return fmt.Errorf("%w: vault_key_id does not match vault public key", ErrCorruptDevice)
	}
	return nil
}

func validateDesktop(td TrustedDesktop) error {
	pub, err := parseP256(td.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: public key: %v", ErrCorruptDesktop, err)
	}
	if deviceID(pub) != td.DesktopID {
		return fmt.Errorf("%w: desktop_id does not match public key", ErrCorruptDesktop)
	}
	return nil
}

func parseP256(der []byte) (*ecdsa.PublicKey, error) {
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 ECDSA key")
	}
	return pub, nil
}

func deviceID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func (d *DB) SaveDevice(td *TrustedDevice) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.db.Exec(`
		DELETE FROM trusted_device;
		INSERT INTO trusted_device (device_id, name, algorithm, public_key_der, vault_key_id, vault_algorithm, vault_public_key_der, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, td.DeviceID, td.Name, td.Algorithm, td.PublicKey, td.VaultKeyID, td.VaultAlgo, td.VaultPublicKey, now, now)
	return err
}

func (d *DB) SaveDesktop(td *TrustedDesktop) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.db.Exec(`
		DELETE FROM trusted_desktop;
		INSERT INTO trusted_desktop (desktop_id, name, algorithm, public_key_der, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, td.DesktopID, td.Name, td.Algorithm, td.PublicKey, now, now)
	return err
}
