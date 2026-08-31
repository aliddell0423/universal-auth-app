package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

func TestDoctorMatrix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("doctor integration test requires a POSIX-ish host script")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	ident, err := identity.LoadOrCreate(filepath.Join(home, ".config", "universal-auth", "desktop-identity.pem"))
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	deviceID := "pixel-123"
	publicKey := "approval-pub-base64"
	vaultKeyID := "vault-key-1"
	vaultPublicKey := "vault-pub-base64"

	brokerSrv := httptest.NewServer(brokerHandler(t, deviceID, publicKey, vaultKeyID, vaultPublicKey, ident))
	defer brokerSrv.Close()

	vaultSrv := httptest.NewServer(vaultHandler(t, vaultKeyID))
	defer vaultSrv.Close()

	configPath := filepath.Join(home, ".config", "universal-auth", "config.json")
	cfg := &config.Config{
		ConfigVersion: 1,
		BrokerURL:     brokerSrv.URL,
		VaultURL:      vaultSrv.URL,
		TrustedDevice: config.TrustedDevice{
			DeviceID:    deviceID,
			Name:        "Pixel 10",
			Algorithm:   "ECDSA_P256_SHA256",
			PublicKey:   publicKey,
			VaultKeyID:  vaultKeyID,
			VaultAlgo:   "ECDH_P256_HKDF_SHA256",
			VaultPubKey: vaultPublicKey,
		},
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("UNIVERSAL_AUTH_CONFIG", configPath)
	t.Setenv("BROKER_TOKEN", "broker-token")
	t.Setenv("VAULT_TOKEN", "vault-token")

	installNativeHost(t, home)

	cases := []struct {
		name      string
		section   string
		origin    string
		wantFails bool
		wantExit  int
	}{
		{name: "healthy system", wantFails: false, wantExit: 0},
		{name: "broker section healthy", section: "broker", wantFails: false, wantExit: 0},
		{name: "vault section with valid origin", section: "vault", origin: "https://example.com", wantFails: false, wantExit: 0},
		{name: "origin missing credential", section: "vault", origin: "https://missing.example", wantFails: true, wantExit: 5},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := config.Load(configPath)
			if err != nil {
				t.Fatalf("load config: %v", err)
			}
			report := Run(context.Background(), cfg, err, Flags{
				Origin:  c.origin,
				Section: c.section,
			})
			if report.HasFails != c.wantFails {
				t.Fatalf("HasFails: got %v, want %v; results=%+v", report.HasFails, c.wantFails, report.Results)
			}
			if report.ExitCode != c.wantExit {
				t.Fatalf("ExitCode: got %d, want %d", report.ExitCode, c.wantExit)
			}
		})
	}
}

func brokerHandler(t *testing.T, deviceID, publicKey, vaultKeyID, vaultPublicKey string, ident *identity.Identity) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/v1/devices/trusted", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(broker.TrustedDevice{
			DeviceID:       deviceID,
			Name:           "Pixel 10",
			Algorithm:      "ECDSA_P256_SHA256",
			PublicKey:      publicKey,
			VaultKeyID:     vaultKeyID,
			VaultAlgorithm: "ECDH_P256_HKDF_SHA256",
			VaultPublicKey: vaultPublicKey,
		})
	})
	mux.HandleFunc("/v1/desktops/trusted", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(broker.TrustedDesktop{
			DesktopID: ident.DesktopID(),
			Name:      "Fedora Desktop",
			Algorithm: "ECDSA_P256_SHA256",
			PublicKey: ident.PublicKey(),
		})
	})
	return mux
}

func vaultHandler(t *testing.T, pixelVaultKeyID string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/v1/credentials/exists", func(w http.ResponseWriter, r *http.Request) {
		origin := r.URL.Query().Get("origin")
		exists := origin == "https://example.com"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vault.ExistsResponse{Exists: exists})
	})
	mux.HandleFunc("/v1/credentials/package", func(w http.ResponseWriter, r *http.Request) {
		origin := r.URL.Query().Get("origin")
		if origin != "https://example.com" {
			http.Error(w, `{"code":"UA-VAULT-002"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&vaultcrypto.Package{
			CredentialID:           "cred-123",
			Origin:                 origin,
			Ciphertext:             "Y2lwaGVydGV4dA",
			CipherNonce:            "Y2lwaGVyLW5vbmNl",
			WrappedDEK:             "d3JhcHBlZC1kZWs",
			WrapNonce:              "d3JhcC1ub25jZQ",
			WrapEphemeralPublicKey: "d3JhcC1lcGhlbWVyYWwtcHVibGljLWtleQ",
			PixelVaultKeyID:        pixelVaultKeyID,
			CryptoVersion:          2,
		})
	})
	return mux
}

func installNativeHost(t *testing.T, home string) {
	t.Helper()
	dir := filepath.Join(home, ".mozilla", "native-messaging-hosts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	hostPath := filepath.Join(dir, "ua-browser-host-test")
	script := []byte(`#!/usr/bin/env python3
import sys, struct, json

length_bytes = sys.stdin.buffer.read(4)
if len(length_bytes) < 4:
    sys.exit(0)
length = struct.unpack('<I', length_bytes)[0]
sys.stdin.buffer.read(length)

resp = {
    "status": "ok",
    "host_version": "test",
    "protocol_version": 2,
    "config_loaded": True,
    "vault_configured": True,
    "pixel_paired": True,
}
data = json.dumps(resp).encode('utf-8')
sys.stdout.buffer.write(struct.pack('<I', len(data)))
sys.stdout.buffer.write(data)
`)
	if err := os.WriteFile(hostPath, script, 0o755); err != nil {
		t.Fatalf("write host: %v", err)
	}

	manifest := map[string]any{
		"name":               "com.aliddell.universalauth",
		"description":        "Universal Auth Native Messaging Host",
		"path":               hostPath,
		"type":               "stdio",
		"allowed_extensions": []string{"universal-auth@aliddell.dev"},
	}
	manifestPath := filepath.Join(dir, "com.aliddell.universalauth.json")
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}
