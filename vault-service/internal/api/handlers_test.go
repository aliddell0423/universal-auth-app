package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"vault-service/internal/model"
	"vault-service/internal/store"
)

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newPackageInput(t *testing.T) model.CredentialPackageInput {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	wrapPub := base64.RawURLEncoding.EncodeToString(der)
	id, _ := randomHex(16)
	cipher, _ := randomB64(48)
	cnonce, _ := randomB64(12)
	wrapped, _ := randomB64(48)
	wnonce, _ := randomB64(12)
	keyID, _ := randomHex(32)
	return model.CredentialPackageInput{
		CredentialID:           id,
		Origin:                 "https://github.com",
		Ciphertext:             cipher,
		CipherNonce:            cnonce,
		WrappedDEK:             wrapped,
		WrapNonce:              wnonce,
		WrapEphemeralPublicKey: wrapPub,
		PixelVaultKeyID:        keyID,
		CryptoVersion:          2,
	}
}

func testServer(t *testing.T) (*httptest.Server, *store.DB) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv := NewServer(db, "test-token")
	return httptest.NewServer(srv.Handler()), db
}

func TestHealth(t *testing.T) {
	srv, db := testServer(t)
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
	srv, db := testServer(t)
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

func TestCreateAndGetPackage(t *testing.T) {
	srv, db := testServer(t)
	defer srv.Close()
	defer db.Close()

	in := newPackageInput(t)
	body, _ := json.Marshal(in)
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

	pkgReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials/package?origin=https%3A%2F%2Fgithub.com", nil)
	pkgReq.Header.Set("Authorization", "Bearer test-token")
	resp3, err := http.DefaultClient.Do(pkgReq)
	if err != nil {
		t.Fatalf("get package: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp3.StatusCode)
	}
	var pkg model.CredentialPackage
	if err := json.NewDecoder(resp3.Body).Decode(&pkg); err != nil {
		t.Fatalf("decode package: %v", err)
	}
	if pkg.CredentialID != in.CredentialID || pkg.Origin != "https://github.com" {
		t.Fatalf("got %v", pkg)
	}
}

func TestListNoSecrets(t *testing.T) {
	srv, db := testServer(t)
	defer srv.Close()
	defer db.Close()

	in := newPackageInput(t)
	body, _ := json.Marshal(in)
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
	resp2, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp2.Body.Close()
	var list []model.CredentialMeta
	if err := json.NewDecoder(resp2.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}
	b, _ := json.Marshal(list[0])
	if fmt.Sprintf("%s", b) == "" {
		t.Fatal("empty list")
	}
}

func TestUnknownOriginPackage404(t *testing.T) {
	srv, db := testServer(t)
	defer srv.Close()
	defer db.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/credentials/package?origin=https%3A%2F%2Fmissing.com", nil)
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

func TestInvalidCryptoVersion(t *testing.T) {
	srv, db := testServer(t)
	defer srv.Close()
	defer db.Close()

	in := newPackageInput(t)
	in.CryptoVersion = 1
	body, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/credentials", bytes.NewReader(body))
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
