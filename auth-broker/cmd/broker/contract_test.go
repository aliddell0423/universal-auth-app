package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func contractPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "..", "testdata", "contracts"}, parts...)...)
}

func TestContractReleaseResponseSerialization(t *testing.T) {
	data, err := os.ReadFile(contractPath("release_response.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var resp ReleaseResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if resp.Protocol == "" {
		t.Fatalf("protocol field was not parsed")
	}
	if resp.CredentialID != "cred-123" {
		t.Fatalf("unexpected credential_id: %s", resp.CredentialID)
	}
	if resp.PackageHash != "hash-abc" {
		t.Fatalf("unexpected package_hash: %s", resp.PackageHash)
	}
	if resp.PixelVaultKeyID != "pixel-key-1" {
		t.Fatalf("unexpected pixel_vault_key_id: %s", resp.PixelVaultKeyID)
	}
	if resp.PixelEphemeralPublic == "" {
		t.Fatalf("pixel_ephemeral_public_key must be present")
	}
	if resp.TransferNonce == "" {
		t.Fatalf("transfer_nonce must be present")
	}
	if resp.EncryptedDEK == "" {
		t.Fatalf("encrypted_dek must be present")
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}

	for _, key := range []string{
		`"protocol"`,
		`"credential_id"`,
		`"package_hash"`,
		`"pixel_vault_key_id"`,
		`"pixel_ephemeral_public_key"`,
		`"transfer_nonce"`,
		`"encrypted_dek"`,
	} {
		if !strings.Contains(string(encoded), key) {
			t.Fatalf("re-encoded response missing key %s: %s", key, string(encoded))
		}
	}
}

func TestContractMissingProtocolFails(t *testing.T) {
	data, err := os.ReadFile(contractPath("failure_cases", "missing_protocol.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var resp ReleaseResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if resp.Protocol != "" {
		t.Fatalf("missing protocol fixture unexpectedly had a protocol: %s", resp.Protocol)
	}

	_, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// A missing protocol is the omission bug this fixture protects against.
	if !strings.Contains(string(data), `"protocol"`) {
		t.Logf("fixture intentionally omits protocol, as expected")
	} else {
		t.Fatalf("fixture unexpectedly contains protocol key")
	}
}

func TestContractApiError(t *testing.T) {
	data, err := os.ReadFile(contractPath("api_error.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var payload struct {
		Code      string `json:"code"`
		Stage     string `json:"stage"`
		Message   string `json:"message"`
		TraceID   string `json:"trace_id"`
		RequestID string `json:"request_id"`
		Retryable bool   `json:"retryable"`
		Action    string `json:"action"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if payload.Code != "UA-BROKER-003" {
		t.Fatalf("unexpected code: %s", payload.Code)
	}
	if payload.TraceID != "trace-7fe91c" {
		t.Fatalf("unexpected trace_id: %s", payload.TraceID)
	}
	if payload.RequestID != "req-abc123" {
		t.Fatalf("unexpected request_id: %s", payload.RequestID)
	}
}
