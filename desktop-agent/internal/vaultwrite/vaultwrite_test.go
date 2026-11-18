package vaultwrite

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

// TestCanonicalMatchesVaultService checks the shared fixture written by
// vault-service/internal/api TestWriteCanonicalFixture.
func TestCanonicalMatchesVaultService(t *testing.T) {
	pkg := &vaultcrypto.Package{
		CredentialID: "00112233445566778899aabbccddeeff", Kind: "login",
		Resource: "https://enterprise.login.utexas.edu", Account: "ajl5646",
		Ciphertext: "Y2lwaGVy", CipherNonce: "bm9uY2U", WrappedDEK: "ZGVr", WrapNonce: "d3JhcA",
		WrapEphemeralPublicKey: "a2V5", PixelVaultKeyID: "pix", CryptoVersion: 3,
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "contracts", "vault_write_canonical.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := Canonical(Op{Op: OpUpdate, CredentialID: pkg.CredentialID, Package: pkg})
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical mismatch:\n%s\nwant:\n%s", got, want)
	}
}

func TestNonceBindsOperation(t *testing.T) {
	pkg := &vaultcrypto.Package{Kind: "login", Resource: "https://x.com", Ciphertext: "a"}
	upd := Nonce(Op{Op: OpUpdate, CredentialID: "aa", Package: pkg})
	del := Nonce(Op{Op: OpDelete, CredentialID: "aa"})
	other := Nonce(Op{Op: OpDelete, CredentialID: "bb"})
	if upd == del || del == other {
		t.Fatal("nonces must differ per operation and credential")
	}
	changed := *pkg
	changed.Account = "work"
	if Nonce(Op{Op: OpUpdate, CredentialID: "aa", Package: &changed}) == upd {
		t.Fatal("nonce must cover the account label")
	}
}
