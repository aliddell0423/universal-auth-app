package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	if req.CreatedAt.IsZero() {
		t.Fatal("created_at not set")
	}
	if req.DecidedAt != nil {
		t.Fatal("decided_at should be nil")
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
	r1 := createRequest(t, srv)
	r2 := createRequest(t, srv)
	approve := `{"decision":"approved"}`
	approveResp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+r1.ID+"/decision", "Bearer "+testToken, strings.NewReader(approve))
	defer approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("approve failed: %d %s", approveResp.StatusCode, body)
	}
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
	req := createRequest(t, srv)
	payload := `{"decision":"approved"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
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
	if got.Status != StatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}
	if got.DecidedAt == nil {
		t.Fatal("decided_at not set")
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
	payload := `{"decision":"approved"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/0123456789abcdef/decision", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAlreadyDecided(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	req := createRequest(t, srv)
	payload := `{"decision":"approved"}`
	resp := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("first decide failed: %d %s", resp.StatusCode, body)
	}
	resp2 := doRequest(t, srv, http.MethodPost, "/v1/requests/"+req.ID+"/decision", "Bearer "+testToken, strings.NewReader(payload))
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
