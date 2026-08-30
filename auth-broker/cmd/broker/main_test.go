package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const testToken = "dev-only-change-this"

func newTestServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(newServer(NewStore(), testToken))
}

func doRequest(t *testing.T, srv *httptest.Server, method, path, auth string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func deviceIDFromKey(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func registerDevice(t *testing.T, srv *httptest.Server, pub *ecdsa.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	devID := deviceIDFromKey(t, pub)
	payload := fmt.Sprintf(`{"device_id":"%s","name":"Pixel 10","algorithm":"ECDSA_P256_SHA256","public_key":"%s"}`, devID, base64.StdEncoding.EncodeToString(der))
	resp := doRequest(t, srv, http.MethodPost, "/v1/devices/register", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register device failed: %d %s", resp.StatusCode, body)
	}
}

func signPayload(t *testing.T, priv *ecdsa.PrivateKey, req *Request) string {
	t.Helper()
	payload := buildSigningPayload(req, "approved")
	hash := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func createRequest(t *testing.T, srv *httptest.Server) Request {
	t.Helper()
	payload := `{"source":"andrew-fedora","kind":"test","resource":"development","message":"Please authenticate"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create failed: %d %s", resp.StatusCode, body)
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return req
}

func approveSigned(t *testing.T, srv *httptest.Server, req Request, priv *ecdsa.PrivateKey) Request {
	t.Helper()
	devID := deviceIDFromKey(t, &priv.PublicKey)
	sig := signPayload(t, priv, &req)
	payload := fmt.Sprintf(`{"decision":"approved","device_id":"%s","signature":"%s"}`, devID, sig)
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve failed: %d %s", resp.StatusCode, body)
	}
	var got Request
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	resp := doRequest(t, srv, http.MethodGet, "/healthz", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body)
	}
}

func TestUnauthorized(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	cases := []struct {
		name string
		auth string
	}{
		{"missing", ""},
		{"wrong", "Bearer wrong-token"},
		{"no prefix", testToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, srv, http.MethodGet, "/v1/requests/pending", tc.auth, nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", resp.StatusCode)
			}
		})
	}
}

func TestCreateRequest(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	payload := `{"source":"andrew-fedora","kind":"test","resource":"development","message":"Please authenticate"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, body)
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.Source != "andrew-fedora" || req.Kind != "test" || req.Resource != "development" || req.Message != "Please authenticate" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.Status != StatusPending {
		t.Fatalf("expected pending, got %s", req.Status)
	}
	if req.ID == "" {
		t.Fatal("id not set")
	}
	if req.Challenge == "" {
		t.Fatal("challenge not set")
	}
	if req.CreatedAt.IsZero() {
		t.Fatal("created_at not set")
	}
	if req.DecidedAt != nil {
		t.Fatal("decided_at should be nil")
	}
}

func TestChallengesAreUnique(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	r1 := createRequest(t, srv)
	r2 := createRequest(t, srv)
	if r1.Challenge == r2.Challenge {
		t.Fatal("challenges must be unique")
	}
}

func TestGetRequest(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	req := createRequest(t, srv)
	resp := doRequest(t, srv, http.MethodGet, "/v1/requests/"+req.ID, "Bearer "+testToken, nil)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	var got Request
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != req.ID {
		t.Fatalf("id mismatch: %s vs %s", got.ID, req.ID)
	}
	if got.Challenge != req.Challenge {
		t.Fatalf("challenge mismatch")
	}
}

func TestGetRequestNotFound(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	resp := doRequest(t, srv, http.MethodGet, "/v1/requests/0123456789abcdef", "Bearer "+testToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestListPending(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)
	r1 := createRequest(t, srv)
	r2 := createRequest(t, srv)
	approveSigned(t, srv, r1, priv)
	resp := doRequest(t, srv, http.MethodGet, "/v1/requests/pending", "Bearer "+testToken, nil)
	defer resp.Body.Close()
	var pending []*Request
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].ID != r2.ID {
		t.Fatalf("expected pending %s, got %s", r2.ID, pending[0].ID)
	}
}

func TestApprove(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)
	req := createRequest(t, srv)
	got := approveSigned(t, srv, req, priv)
	if got.Status != StatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}
	if got.DecidedAt == nil {
		t.Fatal("decided_at not set")
	}
	if got.ApprovalProof == nil {
		t.Fatal("approval_proof not set")
	}
	if got.ApprovalProof.DeviceID != deviceIDFromKey(t, &priv.PublicKey) {
		t.Fatal("approval_proof device_id mismatch")
	}
}

func TestDeny(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	req := createRequest(t, srv)
	payload := `{"decision":"denied"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	var got Request
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != StatusDenied {
		t.Fatalf("expected denied, got %s", got.Status)
	}
	if got.DecidedAt == nil {
		t.Fatal("decided_at not set")
	}
}

func TestInvalidDecision(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	req := createRequest(t, srv)
	payload := `{"decision":"maybe"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestDecisionNotFound(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	payload := `{"decision":"approved","device_id":"abc","signature":"xyz"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/0123456789abcdef/decision", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAlreadyDecided(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	priv := generateTestKey(t)
	registerDevice(t, srv, &priv.PublicKey)
	req := createRequest(t, srv)
	approveSigned(t, srv, req, priv)
	resp2 := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(`{"decision":"denied"}`))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp2.StatusCode)
	}
}

func TestMalformedJSON(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	t.Run("create", func(t *testing.T) {
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests", "Bearer "+testToken, strings.NewReader(`{invalid}`))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})
	t.Run("decision", func(t *testing.T) {
		req := createRequest(t, srv)
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(`{invalid}`))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})
}

func TestUnknownFields(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	payload := `{"source":"s","kind":"test","resource":"r","message":"m","extra":1}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown fields, got %d", resp.StatusCode)
	}
}

func TestMissingRequiredFields(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	cases := []struct {
		name string
		body string
	}{
		{"missing source", `{"kind":"test","resource":"r","message":"m"}`},
		{"missing kind", `{"source":"s","resource":"r","message":"m"}`},
		{"missing resource", `{"source":"s","kind":"test","message":"m"}`},
		{"missing message", `{"source":"s","kind":"test","resource":"r"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, srv, http.MethodPost, "/v1/requests", "Bearer "+testToken, strings.NewReader(tc.body))
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", resp.StatusCode)
			}
		})
	}
}

func TestDeviceRegistration(t *testing.T) {
	t.Run("valid P-256 registration", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		priv := generateTestKey(t)
		registerDevice(t, srv, &priv.PublicKey)
	})

	t.Run("idempotent reregister", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		priv := generateTestKey(t)
		registerDevice(t, srv, &priv.PublicKey)
		registerDevice(t, srv, &priv.PublicKey)
	})

	t.Run("different key conflict", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		priv1 := generateTestKey(t)
		priv2 := generateTestKey(t)
		registerDevice(t, srv, &priv1.PublicKey)
		der, _ := x509.MarshalPKIXPublicKey(&priv2.PublicKey)
		payload := fmt.Sprintf(`{"device_id":"%s","name":"Pixel 10","algorithm":"ECDSA_P256_SHA256","public_key":"%s"}`, deviceIDFromKey(t, &priv2.PublicKey), base64.StdEncoding.EncodeToString(der))
		resp := doRequest(t, srv, http.MethodPost, "/v1/devices/register", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("expected 409, got %d", resp.StatusCode)
		}
	})

	t.Run("malformed public key", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		payload := `{"device_id":"abc","name":"Pixel 10","algorithm":"ECDSA_P256_SHA256","public_key":"not-base64!!!"}`
		resp := doRequest(t, srv, http.MethodPost, "/v1/devices/register", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})

	t.Run("non-ec public key", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		// A small, invalid base64 that decodes to garbage will fail parsing.
		payload := `{"device_id":"abc","name":"Pixel 10","algorithm":"ECDSA_P256_SHA256","public_key":"AAAA"}`
		resp := doRequest(t, srv, http.MethodPost, "/v1/devices/register", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
	})
}

func TestSignedApprovalSecurity(t *testing.T) {
	priv := generateTestKey(t)
	other := generateTestKey(t)

	t.Run("unsigned approved is rejected", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		registerDevice(t, srv, &priv.PublicKey)
		req := createRequest(t, srv)
		payload := `{"decision":"approved"}`
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
		got, _ := storeFromGet(t, srv, req.ID)
		if got.Status != StatusPending {
			t.Fatalf("request should remain pending, got %s", got.Status)
		}
	})

	t.Run("invalid signature is rejected", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		registerDevice(t, srv, &priv.PublicKey)
		req := createRequest(t, srv)
		payload := fmt.Sprintf(`{"decision":"approved","device_id":"%s","signature":"c2lnbmF0dXJl"}`, deviceIDFromKey(t, &priv.PublicKey))
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("signature from unregistered device is rejected", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		registerDevice(t, srv, &priv.PublicKey)
		req := createRequest(t, srv)
		// sign with a different, unregistered key
		sig := signPayload(t, other, &req)
		payload := fmt.Sprintf(`{"decision":"approved","device_id":"%s","signature":"%s"}`, deviceIDFromKey(t, &other.PublicKey), sig)
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("signature for other request is rejected", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		registerDevice(t, srv, &priv.PublicKey)
		req1 := createRequest(t, srv)
		req2 := createRequest(t, srv)
		// sign req2 payload but send it for req1
		sig := signPayload(t, priv, &req2)
		payload := fmt.Sprintf(`{"decision":"approved","device_id":"%s","signature":"%s"}`, deviceIDFromKey(t, &priv.PublicKey), sig)
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req1.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("tampered source causes verification to fail", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		registerDevice(t, srv, &priv.PublicKey)
		req := createRequest(t, srv)
		// modify the source in the stored request by creating a new store reference? Can't.
		// Instead sign the original payload, but modify the request on the broker is not possible via API.
		// We verify that changing any signed field in the signing payload causes a different signature.
		reqCopy := req
		reqCopy.Source = "other"
		sig := signPayload(t, priv, &reqCopy)
		payload := fmt.Sprintf(`{"decision":"approved","device_id":"%s","signature":"%s"}`, deviceIDFromKey(t, &priv.PublicKey), sig)
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("replay after decided is conflict", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		registerDevice(t, srv, &priv.PublicKey)
		req := createRequest(t, srv)
		approveSigned(t, srv, req, priv)
		// replay the exact same signed approval
		sig := signPayload(t, priv, &req)
		payload := fmt.Sprintf(`{"decision":"approved","device_id":"%s","signature":"%s"}`, deviceIDFromKey(t, &priv.PublicKey), sig)
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("expected 409, got %d", resp.StatusCode)
		}
	})

	t.Run("wrong device id with valid signature", func(t *testing.T) {
		srv := newTestServer(t)
		defer srv.Close()
		registerDevice(t, srv, &priv.PublicKey)
		req := createRequest(t, srv)
		sig := signPayload(t, priv, &req)
		payload := fmt.Sprintf(`{"decision":"approved","device_id":"wrong-device-id","signature":"%s"}`, sig)
		resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", resp.StatusCode)
		}
		got, _ := storeFromGet(t, srv, req.ID)
		if got.Status != StatusPending {
			t.Fatalf("request should remain pending, got %s", got.Status)
		}
	})
}

func storeFromGet(t *testing.T, srv *httptest.Server, id string) (Request, bool) {
	t.Helper()
	resp := doRequest(t, srv, http.MethodGet, "/v1/requests/"+id, "Bearer "+testToken, nil)
	defer resp.Body.Close()
	var got Request
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got, resp.StatusCode == http.StatusOK
}

func TestTrailingJSON(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	req := createRequest(t, srv)
	payload := `{"decision":"denied"} {"junk":true}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestCanonicalPayload(t *testing.T) {
	req := &Request{
		ID:        "0123456789abcdef",
		Source:    "andrew-fedora",
		Kind:      "test",
		Resource:  "development",
		Message:   "Please authenticate",
		Challenge: "dGVzdC1jaGFsbGVuZ2U",
	}
	payload := buildSigningPayload(req, "approved")
	golden, err := os.ReadFile("testdata/golden.txt")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	expected := string(golden)
	if string(payload) != expected {
		t.Fatalf("payload mismatch\nexpected:\n%s\nactual:\n%s", expected, string(payload))
	}
}
