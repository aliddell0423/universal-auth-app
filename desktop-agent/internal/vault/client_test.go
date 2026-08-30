package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
			if origin == "https://github.com" {
				_ = json.NewEncoder(w).Encode(ExistsResponse{Exists: true})
			} else {
				_ = json.NewEncoder(w).Encode(ExistsResponse{Exists: false})
			}
		case "/v1/credentials/by-origin":
			if origin == "https://github.com" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(Credential{
					ID:       "abc",
					Origin:   origin,
					Username: "demo",
					Password: "secret",
				})
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func TestCredentialExists(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	exists, err := c.CredentialExists(context.Background(), "https://github.com")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Fatal("expected exists")
	}

	exists, _ = c.CredentialExists(context.Background(), "https://other.com")
	if exists {
		t.Fatal("did not expect exists")
	}
}

func TestGetCredential(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	cred, err := c.GetCredential(context.Background(), "https://github.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cred.Username != "demo" || cred.Password != "secret" {
		t.Fatalf("got %v", cred)
	}

	_, err = c.GetCredential(context.Background(), "https://missing.com")
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
	_, err := c.CredentialExists(ctx, "https://github.com")
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestClientURLQueryEscape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.URL.Query().Get("origin")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ExistsResponse{Exists: origin == "https://example.com?x=1"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	exists, err := c.CredentialExists(context.Background(), "https://example.com?x=1")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Fatalf("expected origin to be escaped correctly")
	}
}

func TestClientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	_, err := c.CredentialExists(context.Background(), "https://example.com")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != fmt.Sprintf("HTTP %d", http.StatusInternalServerError) {
		t.Fatalf("unexpected error: %v", err)
	}
}
