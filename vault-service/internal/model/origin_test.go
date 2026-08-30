package model

import (
	"strings"
	"testing"
)

func TestNormalizeOriginValid(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://github.com", "https://github.com"},
		{"http://127.0.0.1:8765", "http://127.0.0.1:8765"},
		{"https://example.com:8443", "https://example.com:8443"},
		{"https://example.com:443", "https://example.com"},
		{"http://example.com:80", "http://example.com"},
		{"https://example.com/", "https://example.com"},
	}

	for _, tc := range cases {
		got, err := NormalizeOrigin(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeOriginRejections(t *testing.T) {
	cases := []string{
		"ftp://example.com",
		"https://",
		"https://example.com/path",
		"https://example.com?foo=bar",
		"https://example.com#frag",
		"https://user:pass@example.com",
		"not-a-url",
	}

	for _, c := range cases {
		_, err := NormalizeOrigin(c)
		if err == nil {
			t.Fatalf("%q: expected error", c)
		}
	}
}

func TestNormalizeOriginSimilarMalicious(t *testing.T) {
	a, _ := NormalizeOrigin("https://github.com")
	b, _ := NormalizeOrigin("https://github.com.attacker.example")
	if a == b {
		t.Fatal("similar malicious origin must not normalize to the same value")
	}
	if !strings.Contains(b, "github.com.attacker.example") {
		t.Fatalf("got %q", b)
	}
}
