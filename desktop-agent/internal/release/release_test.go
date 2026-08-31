package release

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

func TestReleaseRoundTrip(t *testing.T) {
	pixelVaultPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pixelVaultPub := &pixelVaultPriv.PublicKey
	pixelVaultID := keyFingerprint(pixelVaultPub)

	ident, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "desktop-identity.pem"))
	if err != nil {
		t.Fatal(err)
	}

	pkg, dek, err := vaultcrypto.Encrypt(
		&vaultcrypto.CredentialPlaintext{Username: "tester", Password: "hunter2"},
		"deadbeef",
		"https://github.com",
		pixelVaultID,
		pixelVaultPub,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != 32 {
		t.Fatalf("dek len %d", len(dek))
	}

	store := make(map[string]*broker.Request)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var cr broker.CreateRequest
		if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id := randomHex(t)
		req := broker.Request{
			ID:          id,
			Source:      cr.Source,
			Kind:        cr.Kind,
			Resource:    cr.Resource,
			Message:     cr.Message,
			Challenge:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			ClientNonce: cr.ClientNonce,
			Status:      "pending",
		}
		store[id] = &req
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(req)
	})
	mux.HandleFunc("/v1/requests/", func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/v1/requests/")
		parts := strings.Split(suffix, "/")
		if len(parts) == 2 && parts[1] == "release-request" && r.Method == http.MethodPost {
			id := parts[0]
			var rr broker.ReleaseRequest
			if err := json.NewDecoder(r.Body).Decode(&rr); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			req, ok := store[id]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			resp := simulatePixelResponse(t, req.ID, req.Challenge, req.ClientNonce, rr, dek)
			req.ReleaseResponse = &resp
			req.Status = "released"
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(req)
			return
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			req, ok := store[parts[0]]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(req)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	bc := broker.NewClient(srv.URL, "token")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := SecureRelease(ctx, "https://github.com", pkg, ident, pixelVaultID, bc, "test-trace", 5*time.Second, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("secure release failed: %v", err)
	}
	if result.Username != "tester" || result.Password != "hunter2" {
		t.Fatalf("unexpected plaintext: user=%s pass=%s", result.Username, result.Password)
	}
}

func simulatePixelResponse(t *testing.T, requestID, challenge, clientNonce string, release broker.ReleaseRequest, dek []byte) broker.ReleaseResponse {
	parsed := parseCanonicalPackage(t, release.CredentialPackage)
	credentialID, err := fromB64url(parsed["credential_id"])
	if err != nil {
		t.Fatal(err)
	}
	origin, err := fromB64url(parsed["origin"])
	if err != nil {
		t.Fatal(err)
	}

	fedoraReleasePub, err := parsePublicKey(release.DesktopEphemeralPublic)
	if err != nil {
		t.Fatal(err)
	}

	responsePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	secret, err := sharedECDH(responsePriv.D, fedoraReleasePub)
	if err != nil {
		t.Fatal(err)
	}

	salt := transferSalt(
		requestID,
		challenge,
		clientNonce,
		release.DesktopID,
		credentialID,
		origin,
		release.PackageHash,
		parsed["pixel_vault_key_id"],
	)
	transferKey, err := vaultcrypto.DeriveKey(secret, salt, []byte("universal-auth:release-transfer-key:v1"), 32)
	if err != nil {
		t.Fatal(err)
	}

	responsePubB64, err := publicKeyB64(&responsePriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	aad := transferAAD(
		requestID,
		challenge,
		clientNonce,
		release.DesktopID,
		credentialID,
		origin,
		release.PackageHash,
		parsed["pixel_vault_key_id"],
		release.DesktopEphemeralPublic,
		responsePubB64,
	)

	encDek, nonce, err := vaultcrypto.GCMEncrypt(transferKey, dek, aad)
	if err != nil {
		t.Fatal(err)
	}

	return broker.ReleaseResponse{
		Protocol:             "universal-auth:secure-release:v1",
		CredentialID:         credentialID,
		PackageHash:          release.PackageHash,
		PixelVaultKeyID:      parsed["pixel_vault_key_id"],
		PixelEphemeralPublic: responsePubB64,
		TransferNonce:        base64.RawURLEncoding.EncodeToString(nonce),
		EncryptedDEK:         base64.RawURLEncoding.EncodeToString(encDek),
	}
}

func parseCanonicalPackage(t *testing.T, s string) map[string]string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 || lines[0] != "universal-auth:vault-package:v2" {
		t.Fatalf("invalid package header")
	}
	m := make(map[string]string)
	for _, line := range lines[1:] {
		idx := strings.Index(line, "=")
		if idx < 0 {
			t.Fatalf("invalid package line: %q", line)
		}
		m[line[:idx]] = line[idx+1:]
	}
	return m
}

func fromB64url(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

func keyFingerprint(pub *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum[:])
}
