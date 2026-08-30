package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"vault-service/internal/model"
	"vault-service/internal/store"
)

func testServer(t *testing.T) (*httptest.Server, *store.DB, []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.db")
	db, err := store.Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srv := NewServer(db, "test-token", kek)
	return httptest.NewServer(srv.Handler()), db, kek
}

func TestHealth(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestAuthRequired(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestWrongToken(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestCreateAndRetrieve(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	body, _ := json.Marshal(model.CredentialInput{
		Origin:   "https://github.com",
		Username: "demo",
		Password: "secret",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/credentials", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	existsReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials/exists?origin=https%3A%2F%2Fgithub.com", nil)
	existsReq.Header.Set("Authorization", "Bearer test-token")
	resp2, err := http.DefaultClient.Do(existsReq)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	var exists map[string]bool
	if err := json.NewDecoder(resp2.Body).Decode(&exists); err != nil {
		t.Fatalf("decode exists: %v", err)
	}
	resp2.Body.Close()
	if !exists["exists"] {
		t.Fatal("expected exists true")
	}

	getReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials/by-origin?origin=https%3A%2F%2Fgithub.com", nil)
	getReq.Header.Set("Authorization", "Bearer test-token")
	resp3, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("get: %d", resp3.StatusCode)
	}
	var c model.Credential
	if err := json.NewDecoder(resp3.Body).Decode(&c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if c.Username != "demo" || c.Password != "secret" || c.Origin != "https://github.com" {
		t.Fatalf("got %v", c)
	}
}

func TestListDoesNotExposePasswords(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	body, _ := json.Marshal(model.CredentialInput{
		Origin:   "https://github.com",
		Username: "demo",
		Password: "secret",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/credentials", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	resp.Body.Close()

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials", nil)
	listReq.Header.Set("Authorization", "Bearer test-token")
	resp, err = http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()

	var list []model.CredentialMeta
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}
	b, _ := json.Marshal(list[0])
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "demo") {
		t.Fatalf("list response contains secret: %s", b)
	}
}

func TestUnknownOrigin404(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials/by-origin?origin=https%3A%2F%2Fmissing.com", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestOversizedBody(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	big := fmt.Sprintf("{\"origin\":\"https://example.com\",\"username\":\"%s\",\"password\":\"x\"}", strings.Repeat("x", 64*1024))
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/credentials", bytes.NewReader([]byte(big)))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 400/413, got %d", resp.StatusCode)
	}
}

func TestTrailingJSON(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	body := `{"origin":"https://example.com","username":"u","password":"p"} {"junk":true}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/credentials", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestContextCancellation(t *testing.T) {
	srv, db, _ := testServer(t)
	defer srv.Close()
	defer db.Close()

	body, _ := json.Marshal(model.CredentialInput{Origin: "https://example.com", Username: "u", Password: "p"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/credentials", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	_, err := http.DefaultClient.Do(req)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
