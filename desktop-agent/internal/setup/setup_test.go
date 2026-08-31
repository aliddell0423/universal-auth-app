package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
)

type fakeBroker struct {
	trustedDesktop *broker.TrustedDesktop
	trustedDevice  *broker.TrustedDevice
	registered     []broker.TrustedDesktop
	conflict       bool
}

func (f *fakeBroker) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/v1/desktops/trusted", func(w http.ResponseWriter, r *http.Request) {
		if f.trustedDesktop == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.trustedDesktop)
	})
	mux.HandleFunc("/v1/devices/trusted", func(w http.ResponseWriter, r *http.Request) {
		if f.trustedDevice == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.trustedDevice)
	})
	mux.HandleFunc("/v1/desktops", func(w http.ResponseWriter, r *http.Request) {
		if f.conflict {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintln(w, `{"code":"UA-BROKER-005","stage":"broker.desktop_register","message":"conflict"}`)
			return
		}
		var td broker.TrustedDesktop
		json.NewDecoder(r.Body).Decode(&td)
		f.registered = append(f.registered, td)
		f.trustedDesktop = &td
		w.WriteHeader(http.StatusCreated)
	})
	return mux
}

func vaultReadyHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	return mux
}

func newEnv(t *testing.T) (home, cfgPath, identPath string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	cfgPath = filepath.Join(home, ".config", "universal-auth", "config.json")
	identPath = filepath.Join(home, ".config", "universal-auth", "desktop-identity.pem")
	t.Setenv("UNIVERSAL_AUTH_CONFIG", cfgPath)
	t.Setenv("BROKER_TOKEN", "broker-token")
	t.Setenv("VAULT_TOKEN", "vault-token")
	return home, cfgPath, identPath
}

func stepByName(report *Report, name string) *Step {
	for i := range report.Steps {
		if report.Steps[i].Name == name {
			return &report.Steps[i]
		}
	}
	return nil
}

func TestSetupFreshInstallRegistersDesktop(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	fb := &fakeBroker{}
	brokerSrv := httptest.NewServer(fb.handler(t))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	report := Run(context.Background(), Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		DesktopName:    "Fedora Desktop",
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})

	if report.HasFails {
		t.Fatalf("unexpected failures: %+v", report.Steps)
	}
	if s := stepByName(report, "desktop identity"); s == nil || s.Status != Create {
		t.Fatalf("expected desktop identity to be created, got %+v", s)
	}
	if s := stepByName(report, "desktop registered"); s == nil || s.Status != Create {
		t.Fatalf("expected desktop to be registered, got %+v", s)
	}
	if len(fb.registered) != 1 {
		t.Fatalf("expected one registration, got %d", len(fb.registered))
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.BrokerURL != brokerSrv.URL || cfg.VaultURL != vaultSrv.URL {
		t.Fatalf("config endpoints not persisted: %+v", cfg)
	}
	if cfg.ConfigVersion != config.CurrentConfigVersion {
		t.Fatalf("config version = %d", cfg.ConfigVersion)
	}

	// A Pixel is not registered yet, so this is a remaining human action.
	if s := stepByName(report, "pixel paired"); s == nil || s.Status != Action {
		t.Fatalf("expected pixel pairing action, got %+v", s)
	}
	if !report.HasActions {
		t.Fatalf("expected HasActions to be true")
	}
	if report.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", report.ExitCode)
	}
}

func TestSetupIsIdempotent(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	fb := &fakeBroker{}
	brokerSrv := httptest.NewServer(fb.handler(t))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	opts := Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	}

	first := Run(context.Background(), opts)
	if first.HasFails {
		t.Fatalf("first run failed: %+v", first.Steps)
	}

	second := Run(context.Background(), opts)
	if second.HasFails {
		t.Fatalf("second run failed: %+v", second.Steps)
	}
	if s := stepByName(second, "desktop identity"); s == nil || s.Status != Pass {
		t.Fatalf("second run should reuse identity, got %+v", s)
	}
	if s := stepByName(second, "desktop registered"); s == nil || s.Status != Pass {
		t.Fatalf("second run should not re-register, got %+v", s)
	}
	if s := stepByName(second, "local configuration"); s == nil || s.Status != Pass {
		t.Fatalf("second run should not rewrite config, got %+v", s)
	}
	if len(fb.registered) != 1 {
		t.Fatalf("expected exactly one registration across two runs, got %d", len(fb.registered))
	}
}

func TestSetupRefusesConflictingDesktop(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	fb := &fakeBroker{
		trustedDesktop: &broker.TrustedDesktop{
			DesktopID: "0000000000000000000000000000000000000000000000000000000000000000",
			Name:      "Someone Else",
			Algorithm: "ECDSA_P256_SHA256",
			PublicKey: "other-key",
		},
	}
	brokerSrv := httptest.NewServer(fb.handler(t))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	report := Run(context.Background(), Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})

	s := stepByName(report, "desktop trust conflict")
	if s == nil || s.Status != Fail {
		t.Fatalf("expected desktop trust conflict failure, got %+v", report.Steps)
	}
	if report.ExitCode != 5 {
		t.Fatalf("exit code = %d, want 5", report.ExitCode)
	}
	if len(fb.registered) != 0 {
		t.Fatalf("setup must not register over an existing trusted desktop")
	}
}

func TestSetupRefusesConflictingPixel(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	ident, err := identity.LoadOrCreate(identPath)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	// Pin a Pixel locally that the broker does not agree with.
	cfg := &config.Config{
		BrokerURL: "http://placeholder",
		VaultURL:  "http://placeholder",
		TrustedDevice: config.TrustedDevice{
			DeviceID:   "aaaa",
			Name:       "Old Pixel",
			Algorithm:  "ECDSA_P256_SHA256",
			PublicKey:  "old-key",
			VaultKeyID: "old-vault-key",
		},
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	fb := &fakeBroker{
		trustedDesktop: &broker.TrustedDesktop{
			DesktopID: ident.DesktopID(),
			Name:      "Fedora Desktop",
			Algorithm: "ECDSA_P256_SHA256",
			PublicKey: ident.PublicKey(),
		},
		trustedDevice: &broker.TrustedDevice{
			DeviceID:       "bbbb",
			Name:           "New Pixel",
			Algorithm:      "ECDSA_P256_SHA256",
			PublicKey:      "new-key",
			VaultKeyID:     "new-vault-key",
			VaultAlgorithm: "ECDH_P256_HKDF_SHA256",
			VaultPublicKey: "new-vault-pub",
		},
	}
	brokerSrv := httptest.NewServer(fb.handler(t))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	report := Run(context.Background(), Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})

	s := stepByName(report, "pixel trust conflict")
	if s == nil || s.Status != Fail {
		t.Fatalf("expected pixel trust conflict failure, got %+v", report.Steps)
	}

	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if reloaded.TrustedDevice.DeviceID != "aaaa" {
		t.Fatalf("setup must not overwrite the pinned Pixel, got %s", reloaded.TrustedDevice.DeviceID)
	}
}

func TestSetupPinsPixelWhenPaired(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	fb := &fakeBroker{
		trustedDevice: &broker.TrustedDevice{
			DeviceID:       "pixel-1",
			Name:           "Pixel 10",
			Algorithm:      "ECDSA_P256_SHA256",
			PublicKey:      "approval-pub",
			VaultKeyID:     "vault-key-1",
			VaultAlgorithm: "ECDH_P256_HKDF_SHA256",
			VaultPublicKey: "vault-pub",
		},
	}
	brokerSrv := httptest.NewServer(fb.handler(t))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	report := Run(context.Background(), Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})

	if report.HasFails {
		t.Fatalf("unexpected failures: %+v", report.Steps)
	}
	if s := stepByName(report, "pixel paired"); s == nil || s.Status != Create {
		t.Fatalf("expected pixel to be pinned, got %+v", s)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.TrustedDevice.VaultKeyID != "vault-key-1" {
		t.Fatalf("pixel vault key not pinned: %+v", cfg.TrustedDevice)
	}

	// A second run should be a no-op for the Pixel.
	second := Run(context.Background(), Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})
	if s := stepByName(second, "pixel paired"); s == nil || s.Status != Pass {
		t.Fatalf("second run should report pixel PASS, got %+v", s)
	}
}

func TestSetupCheckOnlyMakesNoChanges(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	fb := &fakeBroker{}
	brokerSrv := httptest.NewServer(fb.handler(t))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	report := Run(context.Background(), Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		CheckOnly:      true,
		SkipNativeHost: true,
	})

	if report.HasFails {
		t.Fatalf("unexpected failures: %+v", report.Steps)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatalf("--check must not write the config file")
	}
	if _, err := os.Stat(identPath); !os.IsNotExist(err) {
		t.Fatalf("--check must not create a desktop identity")
	}
	if len(fb.registered) != 0 {
		t.Fatalf("--check must not register the desktop")
	}
	if !report.HasActions {
		t.Fatalf("--check should report pending actions")
	}
}

func TestSetupRequiresEndpointsOnFirstRun(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	report := Run(context.Background(), Options{
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})

	if !report.HasFails {
		t.Fatalf("expected failure without --broker")
	}
	if s := stepByName(report, "broker URL"); s == nil || s.Status != Fail {
		t.Fatalf("expected broker URL failure, got %+v", report.Steps)
	}
}

func TestSetupReusesConfiguredEndpoints(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	fb := &fakeBroker{}
	brokerSrv := httptest.NewServer(fb.handler(t))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	cfg := &config.Config{BrokerURL: brokerSrv.URL, VaultURL: vaultSrv.URL}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save config: %v", err)
	}

	// No --broker/--vault: the existing config must be reused.
	report := Run(context.Background(), Options{
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})

	if report.HasFails {
		t.Fatalf("unexpected failures: %+v", report.Steps)
	}
	if s := stepByName(report, "broker reachable"); s == nil || s.Status != Pass {
		t.Fatalf("expected broker to be reachable from stored config, got %+v", s)
	}
}

func TestSetupFailsWhenBrokerNotReady(t *testing.T) {
	_, cfgPath, identPath := newEnv(t)

	brokerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, `{"code":"UA-BROKER-009","stage":"broker.readyz","message":"not ready"}`)
	}))
	defer brokerSrv.Close()
	vaultSrv := httptest.NewServer(vaultReadyHandler(t))
	defer vaultSrv.Close()

	report := Run(context.Background(), Options{
		BrokerURL:      brokerSrv.URL,
		VaultURL:       vaultSrv.URL,
		ConfigPath:     cfgPath,
		IdentityPath:   identPath,
		SkipNativeHost: true,
	})

	if s := stepByName(report, "broker reachable"); s == nil || s.Status != Fail {
		t.Fatalf("expected broker reachability failure, got %+v", report.Steps)
	}
	// Dependent steps must not run.
	if stepByName(report, "desktop registered") != nil {
		t.Fatalf("dependent steps must be skipped when the broker is down")
	}
	if report.ExitCode != 5 {
		t.Fatalf("exit code = %d, want 5", report.ExitCode)
	}
}
