package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func putPushRegistration(t *testing.T, srv *httptest.Server, deviceID, provider, installationID string) *http.Response {
	t.Helper()
	payload := fmt.Sprintf(`{"device_id":%q,"provider":%q,"installation_id":%q}`, deviceID, provider, installationID)
	return doRequest(t, srv, http.MethodPut, "/v1/devices/push-registration", "Bearer "+testToken, strings.NewReader(payload))
}

func TestPushRegistrationRequiresTrustedDevice(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// No Pixel is paired yet, so push addressing must be refused.
	resp := putPushRegistration(t, srv, "0000", "fcm", "fid-abc")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
}

func TestPushRegistrationRejectsUnknownDeviceID(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)

	// A push registration claiming a different device must not be accepted:
	// the installation ID can never introduce or change trust.
	resp := putPushRegistration(t, srv, "not-the-trusted-device", "fcm", "fid-abc")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
}

func TestPushRegistrationRejectsUnsupportedProvider(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)
	devID := deviceIDFromKey(t, &priv.PublicKey)

	resp := putPushRegistration(t, srv, devID, "carrier-pigeon", "fid-abc")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPushRegistrationRejectsMissingFields(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)
	devID := deviceIDFromKey(t, &priv.PublicKey)

	resp := putPushRegistration(t, srv, devID, "fcm", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPushRegistrationStoredAndNotEchoed(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)
	devID := deviceIDFromKey(t, &priv.PublicKey)

	resp := putPushRegistration(t, srv, devID, "fcm", "fid-secret-value")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	getResp := doRequest(t, srv, http.MethodGet, "/v1/devices/push-registration", "Bearer "+testToken, nil)
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body=%s", getResp.StatusCode, getBody)
	}

	var out PushRegistrationResponse
	if err := json.Unmarshal(getBody, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.DeviceID != devID {
		t.Fatalf("device_id = %s, want %s", out.DeviceID, devID)
	}
	if out.Provider != "fcm" || !out.Registered {
		t.Fatalf("unexpected response: %+v", out)
	}
	// The installation ID must never be returned to a client.
	if strings.Contains(string(getBody), "fid-secret-value") {
		t.Fatalf("response leaked the installation id: %s", getBody)
	}
}

func TestPushRegistrationIsIdempotentAndUpdatable(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)
	devID := deviceIDFromKey(t, &priv.PublicKey)

	for _, fid := range []string{"fid-1", "fid-1", "fid-2"} {
		resp := putPushRegistration(t, srv, devID, "fcm", fid)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("registering %s: status = %d", fid, resp.StatusCode)
		}
	}
}

func TestPushRegistrationMissingReturns404(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)

	resp := doRequest(t, srv, http.MethodGet, "/v1/devices/push-registration", "Bearer "+testToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPushRegistrationSurvivesBrokerRestart(t *testing.T) {
	dbPath := t.TempDir() + "/broker.db"

	store1, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	srv1 := httptest.NewServer(newServer(store1, testToken))

	priv := generateTestKey(t)
	registerDevice(t, srv1, &priv.PublicKey)
	devID := deviceIDFromKey(t, &priv.PublicKey)

	resp := putPushRegistration(t, srv1, devID, "fcm", "fid-persistent")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	srv1.Close()
	store1.Close()

	// Replace the broker with a new process against the same volume.
	store2, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()

	target, err := store2.PushRegistration()
	if err != nil {
		t.Fatalf("push registration: %v", err)
	}
	if target == nil {
		t.Fatalf("push registration did not survive restart")
	}
	if target.DeviceID != devID {
		t.Fatalf("device_id = %s, want %s", target.DeviceID, devID)
	}
	if target.InstallationID != "fid-persistent" {
		t.Fatalf("installation_id = %s, want fid-persistent", target.InstallationID)
	}
	if target.Provider != "fcm" {
		t.Fatalf("provider = %s, want fcm", target.Provider)
	}
}

// TestSchemaV1UpgradePreservesTrust proves that upgrading an existing broker
// database from schema version 1 keeps the trusted device and desktop rows.
func TestSchemaV1UpgradePreservesTrust(t *testing.T) {
	dbPath := t.TempDir() + "/broker.db"

	priv := generateTestKey(t)
	devID := deviceIDFromKey(t, &priv.PublicKey)
	seedSchemaV1(t, dbPath, &priv.PublicKey, devID)

	// Opening with the current code must migrate to v2 without losing trust.
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("new store on v1 db: %v", err)
	}
	defer store.Close()

	if err := store.Ready(); err != nil {
		t.Fatalf("store not ready after migration: %v", err)
	}

	dev := store.TrustedDevice()
	if dev == nil {
		t.Fatalf("trusted device was lost during migration")
	}
	if dev.DeviceID != devID {
		t.Fatalf("device_id = %s, want %s", dev.DeviceID, devID)
	}
	desk := store.TrustedDesktop()
	if desk == nil {
		t.Fatalf("trusted desktop was lost during migration")
	}
	if desk.DesktopID != devID {
		t.Fatalf("desktop_id = %s, want %s", desk.DesktopID, devID)
	}

	// The new push table must be usable after the upgrade.
	if err := store.SetPushRegistration(devID, "fcm", "fid-after-upgrade"); err != nil {
		t.Fatalf("set push registration after upgrade: %v", err)
	}
	target, err := store.PushRegistration()
	if err != nil || target == nil {
		t.Fatalf("push registration after upgrade: %v (target=%v)", err, target)
	}
}

// seedSchemaV1 writes a database shaped exactly like broker schema version 1,
// containing a trusted device and desktop.
func seedSchemaV1(t *testing.T, dbPath string, pub *ecdsa.PublicKey, id string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE trusted_device (
			device_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			public_key_der BLOB NOT NULL,
			vault_key_id TEXT NOT NULL,
			vault_algorithm TEXT NOT NULL,
			vault_public_key_der BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE trusted_desktop (
			desktop_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			public_key_der BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	now := "2026-01-01T00:00:00Z"
	if _, err := db.Exec(
		`INSERT INTO trusted_device (device_id, name, algorithm, public_key_der, vault_key_id, vault_algorithm, vault_public_key_der, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "Pixel 10", "ECDSA_P256_SHA256", der, id, "ECDH_P256_HKDF_SHA256", der, now, now,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO trusted_desktop (desktop_id, name, algorithm, public_key_der, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, "Fedora Desktop", "ECDSA_P256_SHA256", der, now, now,
	); err != nil {
		t.Fatalf("insert desktop: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)`, now); err != nil {
		t.Fatalf("insert migration: %v", err)
	}
}
