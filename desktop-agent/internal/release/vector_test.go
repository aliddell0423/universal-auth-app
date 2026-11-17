package release

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

// releaseVector is a complete desktop-produced secure release request for a
// v3 package, with the throwaway test keys needed to play the Pixel side.
// The Android unit tests consume the same file to prove both implementations
// agree. Regenerate with UPDATE_VECTORS=1 go test ./internal/release/.
type releaseVector struct {
	RequestID                  string                `json:"request_id"`
	Challenge                  string                `json:"challenge"`
	ClientNonce                string                `json:"client_nonce"`
	DesktopID                  string                `json:"desktop_id"`
	DesktopPublicKey           string                `json:"desktop_public_key"`
	DesktopEphemeralPrivateKey string                `json:"desktop_ephemeral_private_key_pkcs8"`
	PixelVaultPrivateKey       string                `json:"pixel_vault_private_key_pkcs8"`
	PixelVaultKeyID            string                `json:"pixel_vault_key_id"`
	ReleaseRequest             broker.ReleaseRequest `json:"release_request"`
	ExpectedDEK                string                `json:"expected_dek"`
	ExpectedFields             map[string]string     `json:"expected_fields"`
}

func generateReleaseVector(t *testing.T) releaseVector {
	t.Helper()
	pixelPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pixelKeyID := keyFingerprint(&pixelPriv.PublicKey)
	ident, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "desktop-identity.pem"))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{
		"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----",
		"comment":     "vector \"quoted\" comment",
	}
	pkg, dek, err := vaultcrypto.Encrypt(fields, vaultcrypto.KindSSHKey, "ssh/vector", "00112233445566778899aabbccddeeff", pixelKeyID, &pixelPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ephPub, err := publicKeyB64(&ephPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	v := releaseVector{
		RequestID:       "req-vector-1",
		Challenge:       base64.RawURLEncoding.EncodeToString([]byte("vector-challenge-0123456789abcdef")),
		ClientNonce:     base64.RawURLEncoding.EncodeToString([]byte("vector-client-nonce-0123456789ab")),
		DesktopID:       ident.DesktopID(),
		PixelVaultKeyID: pixelKeyID,
		ExpectedDEK:     base64.RawURLEncoding.EncodeToString(dek),
		ExpectedFields:  fields,
	}
	v.DesktopPublicKey = base64.StdEncoding.EncodeToString(ident.PublicKeyDER())
	ephDER, err := x509.MarshalPKCS8PrivateKey(ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	v.DesktopEphemeralPrivateKey = base64.StdEncoding.EncodeToString(ephDER)
	pixelDER, err := x509.MarshalPKCS8PrivateKey(pixelPriv)
	if err != nil {
		t.Fatal(err)
	}
	v.PixelVaultPrivateKey = base64.StdEncoding.EncodeToString(pixelDER)

	sum := sha256.Sum256(canonicalReleaseRequest(2, v.RequestID, v.Challenge, v.ClientNonce, v.DesktopID,
		"credential_release", pkg.Resource, pkg.CredentialID, vaultcrypto.Hash(pkg), ephPub, pixelKeyID))
	sig, err := ident.Sign(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	v.ReleaseRequest = broker.ReleaseRequest{
		Protocol:               ReleaseProtocolV2,
		DesktopID:              v.DesktopID,
		DesktopAlgorithm:       "ECDSA_P256_SHA256",
		DesktopEphemeralPublic: ephPub,
		CredentialPackage:      string(vaultcrypto.Canonical(pkg)),
		PackageHash:            vaultcrypto.Hash(pkg),
		DesktopSignature:       sig,
	}
	return v
}

func TestContractReleaseVectorV3(t *testing.T) {
	path := contractPath("release_vector_v3.json")
	if os.Getenv("UPDATE_VECTORS") == "1" {
		data, err := json.MarshalIndent(generateReleaseVector(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var v releaseVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	pkg := packageFromCanonical(t, v.ReleaseRequest.CredentialPackage)
	if pkg.CryptoVersion != vaultcrypto.CryptoVersionV3 || pkg.Kind != vaultcrypto.KindSSHKey {
		t.Fatalf("unexpected package: %+v", pkg)
	}
	if vaultcrypto.Hash(pkg) != v.ReleaseRequest.PackageHash {
		t.Fatal("package hash mismatch")
	}

	// The current signing code must still accept the stored desktop signature.
	pubDER, _ := base64.StdEncoding.DecodeString(v.DesktopPublicKey)
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonicalReleaseRequest(2, v.RequestID, v.Challenge, v.ClientNonce, v.DesktopID,
		"credential_release", pkg.Resource, pkg.CredentialID, v.ReleaseRequest.PackageHash,
		v.ReleaseRequest.DesktopEphemeralPublic, v.PixelVaultKeyID))
	sig, _ := base64.StdEncoding.DecodeString(v.ReleaseRequest.DesktopSignature)
	if !ecdsa.VerifyASN1(pubAny.(*ecdsa.PublicKey), sum[:], sig) {
		t.Fatal("desktop signature does not verify against the canonical release request")
	}

	// The current crypto must still open the stored package.
	privDER, _ := base64.StdEncoding.DecodeString(v.PixelVaultPrivateKey)
	privAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := vaultcrypto.Decrypt(pkg, privAny.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !reflect.DeepEqual(pt.Fields, v.ExpectedFields) {
		t.Fatalf("fields mismatch: %v", pt.Fields)
	}
}
