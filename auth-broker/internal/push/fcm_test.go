package push

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func testSender(t *testing.T, tokenSrv, sendSrv *httptest.Server) (*FCMSender, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &FCMSender{
		projectID: "test-project",
		email:     "svc@test.iam.gserviceaccount.com",
		key:       key,
		tokenURI:  tokenSrv.URL,
		sendURL:   sendSrv.URL,
		http:      tokenSrv.Client(),
	}
	return s, key
}

var jwtVerifyKey atomic.Value

func TestFCMSenderSendsMessage(t *testing.T) {
	var tokenCalls, sendCalls atomic.Int32
	var gotAuth, gotBody string

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("token form: %v", err)
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type: %q", r.Form.Get("grant_type"))
		}
		assertion := r.Form.Get("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Fatalf("assertion parts: %d", len(parts))
		}
		// Verify the JWT signature with the public key.
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		jwtKey, _ := jwtVerifyKey.Load().(*rsa.PrivateKey)
		if jwtKey == nil {
			t.Error("jwt verify key not set")
		} else if err := rsa.VerifyPKCS1v15(&jwtKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("jwt signature: %v", err)
		}
		var claims map[string]any
		claimBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if err := json.Unmarshal(claimBytes, &claims); err != nil {
			t.Errorf("claims: %v", err)
		}
		if claims["iss"] != "svc@test.iam.gserviceaccount.com" {
			t.Errorf("iss: %v", claims["iss"])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok123", "expires_in": 3600})
	}))
	defer tokenSrv.Close()

	sendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendCalls.Add(1)
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"projects/test-project/messages/1"}`))
	}))
	defer sendSrv.Close()

	s, key := testSender(t, tokenSrv, sendSrv)
	jwtVerifyKey.Store(key)
	defer jwtVerifyKey.Store((*rsa.PrivateKey)(nil))
	if err := s.SendCredentialRequest(context.Background(), "fcm-token-abc", "req-123"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if tokenCalls.Load() != 1 || sendCalls.Load() != 1 {
		t.Fatalf("calls: token=%d send=%d", tokenCalls.Load(), sendCalls.Load())
	}
	if gotAuth != "Bearer tok123" {
		t.Fatalf("auth header: %q", gotAuth)
	}
	var msg struct {
		Message struct {
			Token string            `json:"token"`
			Data  map[string]string `json:"data"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(gotBody), &msg); err != nil {
		t.Fatalf("body: %v", err)
	}
	if msg.Message.Token != "fcm-token-abc" || msg.Message.Data[KeyRequestID] != "req-123" {
		t.Fatalf("unexpected message: %s", gotBody)
	}

	// Second send reuses the cached token.
	if err := s.SendCredentialRequest(context.Background(), "fcm-token-abc", "req-456"); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token should be cached, got %d calls", tokenCalls.Load())
	}
}
