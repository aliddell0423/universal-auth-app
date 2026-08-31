package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		origin := r.URL.Query().Get("origin")
		switch r.URL.Path {
		case "/v1/credentials/exists":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ExistsResponse{Exists: origin == "https://github.com"})
		case "/v1/credentials/package":
			if origin == "https://github.com" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(vaultcrypto.Package{
					CredentialID:           "aabbcc",
					Origin:                 origin,
					Ciphertext:             "cipher",
					CipherNonce:            "nonce",
					WrappedDEK:             "wrapped",
					WrapNonce:              "wnonce",
					WrapEphemeralPublicKey: "wrapephem",
					PixelVaultKeyID:        "pixelkey",
					CryptoVersion:          2,
				})
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		case "/v1/credentials":
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func TestCredentialExists(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	exists, err := c.CredentialExists(context.Background(), "https://github.com", "")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Fatal("expected exists")
	}

	exists, _ = c.CredentialExists(context.Background(), "https://other.com", "")
	if exists {
		t.Fatal("did not expect exists")
	}
}

func TestGetPackage(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	pkg, err := c.GetPackage(context.Background(), "https://github.com", "")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if pkg.CredentialID != "aabbcc" || pkg.CryptoVersion != 2 {
		t.Fatalf("got %v", pkg)
	}

	_, err = c.GetPackage(context.Background(), "https://missing.com", "")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestClientUsesContext(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	c.client.Timeout = 1 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.CredentialExists(ctx, "https://github.com", "")
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestClientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	_, err := c.CredentialExists(context.Background(), "https://example.com", "")
	if err == nil {
		t.Fatal("expected error")
	}
	want := fmt.Sprintf("HTTP %d", http.StatusInternalServerError)
	if err.Error() == want {
		t.Fatalf("error should include body, got: %v", err)
	}
}

func TestCreatePackage(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	keyID := sha256.Sum256(der)

	pkg := &vaultcrypto.Package{
		CredentialID:           hex.EncodeToString([]byte("id")),
		Origin:                 "https://github.com",
		Ciphertext:             "ct",
		CipherNonce:            "cn",
		WrappedDEK:             "wd",
		WrapNonce:              "wn",
		WrapEphemeralPublicKey: "wrapephem",
		PixelVaultKeyID:        hex.EncodeToString(keyID[:]),
		CryptoVersion:          2,
	}
	c := NewClient(srv.URL, "test-token")
	if err := c.CreatePackage(context.Background(), pkg, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
}
