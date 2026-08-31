package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/devices/trusted":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TrustedDevice{
				DeviceID:  "fingerprint",
				Name:      "Pixel 10",
				Algorithm: "ECDSA_P256_SHA256",
				PublicKey: "cHVibGlj",
			})
		case "/v1/requests":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var c CreateRequest
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(Request{
				ID:          "abc123",
				Source:      c.Source,
				Kind:        c.Kind,
				Resource:    c.Resource,
				Message:     c.Message,
				Challenge:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 32 bytes raw
				ClientNonce: c.ClientNonce,
				Status:      "pending",
			})
		case "/v1/requests/abc123":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(Request{ID: "abc123", Status: "pending"})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func TestClientGetTrustedDevice(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	c := NewClient(srv.URL, "test-token")
	td, err := c.GetTrustedDevice(context.Background(), "")
	if err != nil {
		t.Fatalf("get trusted device: %v", err)
	}
	if td.DeviceID != "fingerprint" {
		t.Fatalf("unexpected device id: %s", td.DeviceID)
	}
}

func TestClientCreateRequest(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	c := NewClient(srv.URL, "test-token")
	req, err := c.CreateRequest(context.Background(), CreateRequest{
		Source:      "andrew-fedora",
		Kind:        "test",
		Resource:    "desktop-test",
		Message:     "hi",
		ClientNonce: "bm9uY2U",
	}, "")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if req.ID != "abc123" {
		t.Fatalf("unexpected id: %s", req.ID)
	}
	if req.Status != "pending" {
		t.Fatalf("unexpected status: %s", req.Status)
	}
}

func TestClientValidatePendingResponse(t *testing.T) {
	c := NewClient("", "")
	want := CreateRequest{
		Source:      "andrew-fedora",
		Kind:        "test",
		Resource:    "desktop-test",
		Message:     "hi",
		ClientNonce: "bm9uY2U",
	}
	req := Request{
		ID:          "abc123",
		Source:      "andrew-fedora",
		Kind:        "test",
		Resource:    "desktop-test",
		Message:     "hi",
		Challenge:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientNonce: "bm9uY2U",
		Status:      "pending",
	}
	if err := c.ValidatePendingResponse(req, want); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestClientValidatePendingResponseTampered(t *testing.T) {
	c := NewClient("", "")
	want := CreateRequest{
		Source:      "andrew-fedora",
		Kind:        "test",
		Resource:    "desktop-test",
		Message:     "hi",
		ClientNonce: "bm9uY2U",
	}
	req := Request{
		ID:          "abc123",
		Source:      "other-fedora",
		Kind:        "test",
		Resource:    "desktop-test",
		Message:     "hi",
		Challenge:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientNonce: "bm9uY2U",
		Status:      "pending",
	}
	if err := c.ValidatePendingResponse(req, want); err == nil {
		t.Fatal("expected error for tampered source")
	}
}

func TestClientValidatePendingResponseBadChallenge(t *testing.T) {
	c := NewClient("", "")
	want := CreateRequest{ClientNonce: "bm9uY2U"}
	req := Request{
		ID:          "abc123",
		ClientNonce: "bm9uY2U",
		Status:      "pending",
		Challenge:   "bm90MzJieXRlcw",
	}
	if err := c.ValidatePendingResponse(req, want); err == nil {
		t.Fatal("expected error for bad challenge")
	}
}

func TestClientUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "wrong-token")
	_, err := c.GetTrustedDevice(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for unauthorized")
	}
}
