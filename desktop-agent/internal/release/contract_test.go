package release

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

func contractPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "..", "testdata", "contracts"}, parts...)...)
}

func TestContractVaultPackageV2Canonical(t *testing.T) {
	data, err := os.ReadFile(contractPath("vault_package_v2_canonical.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	expected := strings.TrimSpace(string(data))

	pkg := &vaultcrypto.Package{
		CredentialID:           "cred-123",
		Origin:                 "https://example.com",
		Ciphertext:             "Y2lwaGVydGV4dA",
		CipherNonce:            "Y2lwaGVyLW5vbmNl",
		WrappedDEK:             "d3JhcHBlZC1kZWs",
		WrapNonce:              "d3JhcC1ub25jZQ",
		WrapEphemeralPublicKey: "d3JhcC1lcGhlbWVyYWwtcHVibGljLWtleQ",
		PixelVaultKeyID:        "pixel-key-1",
		CryptoVersion:          2,
	}

	canonical := strings.TrimSpace(string(vaultcrypto.Canonical(pkg)))
	if canonical != expected {
		t.Fatalf("canonical package mismatch\nexpected:\n%s\n\nactual:\n%s", expected, canonical)
	}

	// Hash must be deterministic and round-trip with the canonical representation.
	hash := vaultcrypto.Hash(pkg)
	if hash == "" {
		t.Fatalf("hash must not be empty")
	}
	if strings.Contains(hash, "=") {
		t.Fatalf("hash must be unpadded Base64URL")
	}
}

func TestContractReleaseRequestPackageHash(t *testing.T) {
	data, err := os.ReadFile(contractPath("release_request.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var req broker.ReleaseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatalf("unmarshal release request: %v", err)
	}

	// Recompute the package hash and ensure it is consistent with the canonical package.
	pkg := packageFromCanonical(t, req.CredentialPackage)

	hash := vaultcrypto.Hash(pkg)
	if hash != req.PackageHash {
		t.Fatalf("package hash mismatch: fixture=%s computed=%s", req.PackageHash, hash)
	}
}

func TestContractReleaseRequestWrongPackageHashFails(t *testing.T) {
	data, err := os.ReadFile(contractPath("failure_cases", "wrong_package_hash.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var req broker.ReleaseRequest
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatalf("unmarshal release request: %v", err)
	}

	pkg := packageFromCanonical(t, req.CredentialPackage)

	hash := vaultcrypto.Hash(pkg)
	if hash == req.PackageHash {
		t.Fatalf("expected wrong package hash to differ, but both are %s", hash)
	}
}

func TestContractCanonicalReleaseRequestString(t *testing.T) {
	data, err := os.ReadFile(contractPath("canonical_release_request.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	expected := strings.TrimSpace(string(data))

	actual := strings.TrimSpace(string(canonicalReleaseRequest(
		2,
		"req-abc123",
		"challenge-value",
		"client-nonce-1",
		"desktop-abc",
		"credential_release",
		"https://example.com",
		"cred-123",
		"hash-abc",
		"ephemeral_pub_base64url",
		"pixel-key-1",
	)))

	if actual != expected {
		t.Fatalf("canonical release request mismatch\nexpected:\n%s\n\nactual:\n%s", expected, actual)
	}
}

func TestContractReleaseResponseFields(t *testing.T) {
	data, err := os.ReadFile(contractPath("release_response.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var resp broker.ReleaseResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal release response: %v", err)
	}

	if resp.Protocol == "" {
		t.Fatalf("protocol must be present in release response")
	}
	if resp.CredentialID == "" || resp.PackageHash == "" || resp.PixelVaultKeyID == "" ||
		resp.PixelEphemeralPublic == "" || resp.TransferNonce == "" || resp.EncryptedDEK == "" {
		t.Fatalf("release response is missing required fields")
	}
}

func TestContractVaultPackageV3Canonical(t *testing.T) {
	data, err := os.ReadFile(contractPath("vault_package_v3_canonical.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	expected := strings.TrimSpace(string(data))

	pkg := &vaultcrypto.Package{
		CredentialID:           "cred-123",
		Kind:                   "login",
		Resource:               "https://example.com",
		Ciphertext:             "Y2lwaGVydGV4dA",
		CipherNonce:            "Y2lwaGVyLW5vbmNl",
		WrappedDEK:             "d3JhcHBlZC1kZWs",
		WrapNonce:              "d3JhcC1ub25jZQ",
		WrapEphemeralPublicKey: "d3JhcC1lcGhlbWVyYWwtcHVibGljLWtleQ",
		PixelVaultKeyID:        "pixel-key-1",
		CryptoVersion:          3,
	}

	canonical := strings.TrimSpace(string(vaultcrypto.Canonical(pkg)))
	if canonical != expected {
		t.Fatalf("canonical package mismatch\nexpected:\n%s\n\nactual:\n%s", expected, canonical)
	}
	if vaultcrypto.Hash(pkg) != "cdR0geVwyC-m_O6Je3Y48iDPsMgTW40LJFEQG8o8weY" {
		t.Fatalf("unexpected v3 package hash")
	}
}

func packageFromCanonical(t *testing.T, s string) *vaultcrypto.Package {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		t.Fatalf("invalid package header")
	}
	var version int
	switch lines[0] {
	case "universal-auth:vault-package:v2":
		version = 2
	case "universal-auth:vault-package:v3":
		version = 3
	default:
		t.Fatalf("invalid package header %q", lines[0])
	}
	m := make(map[string]string)
	for _, line := range lines[1:] {
		idx := strings.Index(line, "=")
		if idx < 0 {
			t.Fatalf("invalid package line: %q", line)
		}
		m[line[:idx]] = line[idx+1:]
	}
	decode := func(k string) string {
		v, ok := m[k]
		if !ok {
			t.Fatalf("missing %s", k)
		}
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			return v
		}
		return string(b)
	}
	cv, err := strconv.Atoi(m["crypto_version"])
	if err != nil {
		t.Fatalf("invalid crypto_version: %v", err)
	}
	pkg := &vaultcrypto.Package{
		CredentialID:           decode("credential_id"),
		Ciphertext:             m["ciphertext"],
		CipherNonce:            m["cipher_nonce"],
		WrappedDEK:             m["wrapped_dek"],
		WrapNonce:              m["wrap_nonce"],
		WrapEphemeralPublicKey: m["wrap_ephemeral_public_key"],
		PixelVaultKeyID:        m["pixel_vault_key_id"],
		CryptoVersion:          cv,
	}
	if version == 3 {
		pkg.Kind = decode("kind")
		pkg.Resource = decode("resource")
	} else {
		pkg.Origin = decode("origin")
	}
	return pkg
}
