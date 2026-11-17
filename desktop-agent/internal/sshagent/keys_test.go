package sshagent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestIdentityFromFields(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	edBlock, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	ecBlock, err := ssh.MarshalPrivateKey(ecPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(edPriv, "", []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	// vaultctl strips the trailing newline of file-backed fields.
	trim := func(b *pem.Block) string { return strings.TrimRight(string(pem.EncodeToMemory(b)), "\n") }

	id, err := IdentityFromFields("ssh/ed", map[string]string{FieldPrivateKey: trim(edBlock), FieldComment: "laptop"})
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	if id.Comment != "laptop" {
		t.Fatalf("comment: %q", id.Comment)
	}
	id2, err := IdentityFromFields("ssh/ec", map[string]string{FieldPrivateKey: trim(ecBlock)})
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	if id2.Comment != "ssh/ec" {
		t.Fatalf("fallback comment: %q", id2.Comment)
	}
	// Both must be usable by the agent server.
	srv, err := NewServer([]Identity{id, id2})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if len(srv.Identities()) != 2 {
		t.Fatalf("identities: %d", len(srv.Identities()))
	}

	if _, err := IdentityFromFields("ssh/enc", map[string]string{FieldPrivateKey: trim(encBlock)}); err == nil {
		t.Fatal("expected error for encrypted key without passphrase")
	}
	if _, err := IdentityFromFields("ssh/enc", map[string]string{FieldPrivateKey: trim(encBlock), FieldPassphrase: "s3cret"}); err != nil {
		t.Fatalf("encrypted key with passphrase: %v", err)
	}
	if _, err := IdentityFromFields("ssh/none", map[string]string{}); err == nil {
		t.Fatal("expected error for missing private_key")
	}
	if _, err := IdentityFromFields("ssh/bad", map[string]string{FieldPrivateKey: "not a key"}); err == nil {
		t.Fatal("expected error for garbage key")
	}
}
