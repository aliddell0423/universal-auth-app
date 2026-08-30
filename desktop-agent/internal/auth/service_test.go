package auth

import (
	"os"
	"strings"
	"testing"
)

func TestDefaultSource(t *testing.T) {
	h, _ := os.Hostname()
	var want string
	if h == "" {
		want = "andrew-fedora"
	} else {
		want = strings.Split(h, ".")[0] + "-fedora"
	}
	if got := DefaultSource(); got != want {
		t.Fatalf("DefaultSource() = %q, want %q", got, want)
	}
}

func TestGenerateClientNonce(t *testing.T) {
	n, err := generateClientNonce()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if n == "" {
		t.Fatal("client nonce is empty")
	}
	// 32 unpadded base64url bytes -> 43 characters.
	if len(n) != 43 {
		t.Fatalf("client nonce length = %d, want 43", len(n))
	}
}
