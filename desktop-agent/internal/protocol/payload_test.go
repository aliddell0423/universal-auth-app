package protocol

import (
	"os"
	"testing"
)

func TestCanonicalPayload(t *testing.T) {
	payload := BuildSigningPayload(
		"0123456789abcdef",
		"dGVzdC1jaGFsbGVuZ2U",
		"dGVzdC1jbGllbnQtbm9uY2U",
		"andrew-fedora",
		"test",
		"development",
		"Please authenticate",
		"approved",
	)
	golden, err := os.ReadFile("testdata/golden.txt")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	expected := string(golden)
	if string(payload) != expected {
		t.Fatalf("payload mismatch\nexpected:\n%s\nactual:\n%s", expected, string(payload))
	}
}
