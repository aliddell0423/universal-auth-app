package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func setupTestStore(t *testing.T, data map[string]Credential, perm os.FileMode) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	path := filepath.Join(tmp, ".config", "universal-auth", "dev-credentials.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, perm); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestStoreHasExactMatch(t *testing.T) {
	p := setupTestStore(t, map[string]Credential{
		"http://127.0.0.1:8765": {
			Username: "demo@universalauth.test",
			Password: "development-password-only",
		},
	}, 0o600)
	store, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !store.Has("http://127.0.0.1:8765") {
		t.Fatal("expected store to contain http://127.0.0.1:8765")
	}
}

func TestStoreGet(t *testing.T) {
	p := setupTestStore(t, map[string]Credential{
		"http://127.0.0.1:8765": {
			Username: "demo@universalauth.test",
			Password: "development-password-only",
		},
	}, 0o600)
	store, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	c, err := store.Get("http://127.0.0.1:8765")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.Username != "demo@universalauth.test" || c.Password != "development-password-only" {
		t.Fatalf("got %v", c)
	}
}

func TestStoreUnknownOrigin(t *testing.T) {
	p := setupTestStore(t, map[string]Credential{
		"http://127.0.0.1:8765": {Username: "u", Password: "p"},
	}, 0o600)
	store, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if store.Has("https://github.com") {
		t.Fatal("did not expect https://github.com to be present")
	}
	_, err = store.Get("https://github.com")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStoreSimilarMaliciousOrigin(t *testing.T) {
	p := setupTestStore(t, map[string]Credential{
		"https://github.com": {Username: "u", Password: "p"},
	}, 0o600)
	store, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if store.Has("https://github.com.attacker.example") {
		t.Fatal("similar malicious origin must not match")
	}
}

func TestStoreOverlyPermissiveFile(t *testing.T) {
	p := setupTestStore(t, map[string]Credential{
		"http://127.0.0.1:8765": {Username: "u", Password: "p"},
	}, 0o644)
	_, err := Open(p)
	if err == nil {
		t.Fatal("expected error for overly permissive credential file")
	}
}
