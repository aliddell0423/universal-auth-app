package sshagent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func mustBlob(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return p.Marshal()
}

func startTestAgent(t *testing.T, ids []Identity) (addr string, cleanup func()) {
	t.Helper()
	srv, err := NewServer(ids)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	dir := t.TempDir()
	addr = filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx, ln)
	return addr, func() {
		cancel()
		ln.Close()
		_ = os.Remove(addr)
	}
}

func dialAgent(t *testing.T, addr string) agent.ExtendedAgent {
	t.Helper()
	conn, err := net.DialTimeout("unix", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return agent.NewClient(conn)
}

func TestIdentitiesAndEd25519Sign(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ids := []Identity{{Comment: "ed25519 test", Signer: priv}}
	addr, cleanup := startTestAgent(t, ids)
	defer cleanup()

	c := dialAgent(t, addr)
	keys, err := c.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Comment != "ed25519 test" {
		t.Fatalf("comment: %q", keys[0].Comment)
	}

	data := []byte("hello ssh agent")
	sig, err := c.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig.Format != "ssh-ed25519" {
		t.Fatalf("format: %q", sig.Format)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), data, sig.Blob) {
		t.Fatal("ed25519 signature did not verify")
	}
	verifyWithOpenSSHRules(t, keys[0].Blob, data, sig)
}

func TestECDSASign(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ids := []Identity{{Comment: "ecdsa", Signer: priv}}
	addr, cleanup := startTestAgent(t, ids)
	defer cleanup()

	c := dialAgent(t, addr)
	keys, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("ecdsa payload")
	sig, err := c.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig.Format != "ecdsa-sha2-nistp256" {
		t.Fatalf("format: %q", sig.Format)
	}

	verifyWithOpenSSHRules(t, keys[0].Blob, data, sig)
}

func TestECDSAP384Sign(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr, cleanup := startTestAgent(t, []Identity{{Signer: priv}})
	defer cleanup()

	c := dialAgent(t, addr)
	keys, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("p384 payload")
	sig, err := c.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifyWithOpenSSHRules(t, keys[0].Blob, data, sig)
}

// verifyWithOpenSSHRules checks a signature the way an SSH server would,
// using x/crypto/ssh's wire-format parsing rather than our own codec.
func verifyWithOpenSSHRules(t *testing.T, blob, data []byte, sig *ssh.Signature) {
	t.Helper()
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("signature rejected: %v", err)
	}
}

func TestRSASign(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ids := []Identity{{Comment: "rsa", Signer: priv}}
	addr, cleanup := startTestAgent(t, ids)
	defer cleanup()

	c := dialAgent(t, addr)
	keys, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("rsa payload")
	sig, err := c.Sign(keys[0], data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Default RSA flag is SHA1.
	if sig.Format != "ssh-rsa" {
		t.Fatalf("format: %q", sig.Format)
	}
	sigBytes := sig.Blob
	h := sha1Sum(data)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA1, h[:], sigBytes); err != nil {
		t.Fatalf("rsa sha1 verify: %v", err)
	}
	verifyWithOpenSSHRules(t, keys[0].Blob, data, sig)
}

func TestRSASHA2Flag(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ids := []Identity{{Comment: "rsa", Signer: priv}}
	addr, cleanup := startTestAgent(t, ids)
	defer cleanup()

	c := dialAgent(t, addr)
	keys, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("rsa payload sha2")
	sig, err := c.Sign(keys[0], data)
	if err != nil {
		t.Fatal(err)
	}
	_ = sig

	// Sign again with explicit SHA2-512 flag via raw protocol.
	conn, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := newWriter()
	putString(payload, keys[0].Blob)
	putString(payload, data)
	putU32(payload, flagRSA_SHA2_512)
	if err := writeMessage(conn, reqSign, payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	mt, resp, err := readResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	if mt != msgSignAns {
		t.Fatalf("expected sign answer, got type %d", mt)
	}
	sr := &reader{b: resp}
	sigField, _ := sr.string()
	sigr := &reader{b: sigField}
	alg, _ := sigr.string()
	sigBytes, _ := sigr.string()
	if string(alg) != "rsa-sha2-512" {
		t.Fatalf("alg: %q", alg)
	}
	h := sha512.Sum512(data)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA512, h[:], sigBytes); err != nil {
		t.Fatalf("rsa sha512 verify: %v", err)
	}
}

func TestSignUnknownKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ids := []Identity{{Signer: priv}}
	addr, cleanup := startTestAgent(t, ids)
	defer cleanup()

	// Forge a key not in the agent via a raw sign request.
	conn, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	p, _ := ssh.NewPublicKey(other.Public())
	payload := newWriter()
	putString(payload, p.Marshal())
	putString(payload, []byte("x"))
	putU32(payload, 0)
	if err := writeMessage(conn, reqSign, payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	mt, _, err := readResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	if mt != msgFailure {
		t.Fatalf("expected failure for unknown key, got %d", mt)
	}
}

func TestRemoveAll(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ids := []Identity{{Signer: priv}}
	addr, cleanup := startTestAgent(t, ids)
	defer cleanup()

	conn, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeMessage(conn, reqRemoveAll, nil); err != nil {
		t.Fatal(err)
	}
	mt, _, err := readResponse(conn)
	if err != nil {
		t.Fatal(err)
	}
	if mt != msgSuccess {
		t.Fatalf("expected success, got %d", mt)
	}

	c := agent.NewClient(conn)
	keys, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys after remove all, got %d", len(keys))
	}
}

func readResponse(conn net.Conn) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	body := make([]byte, n-1)
	if _, err := readFull(conn, body); err != nil {
		return 0, nil, err
	}
	return hdr[4], body, nil
}

func readFull(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func sha1Sum(b []byte) []byte {
	hasher := hashFor(crypto.SHA1)()
	hasher.Write(b)
	return hasher.Sum(nil)
}

func TestAcquirePerSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blob, err := PublicBlob(priv)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	id := Identity{Comment: "lazy", Blob: blob, Acquire: func() (crypto.Signer, error) {
		calls++
		return priv, nil
	}}
	addr, cleanup := startTestAgent(t, []Identity{id})
	defer cleanup()

	c := dialAgent(t, addr)
	keys, err := c.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("list: %v / %d", err, len(keys))
	}
	if calls != 0 {
		t.Fatalf("listing identities must not acquire the key, got %d calls", calls)
	}
	for i := 1; i <= 2; i++ {
		sig, err := c.Sign(keys[0], []byte("payload"))
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		verifyWithOpenSSHRules(t, keys[0].Blob, []byte("payload"), sig)
		if calls != i {
			t.Fatalf("expected %d acquisitions, got %d", i, calls)
		}
	}
}

func TestAcquireFailureAndMismatchRefuseToSign(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	blob, _ := PublicBlob(priv)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	blob2, _ := PublicBlob(priv2)
	ids := []Identity{
		{Comment: "swapped", Blob: blob, Acquire: func() (crypto.Signer, error) { return other, nil }},
		{Comment: "denied", Blob: blob2, Acquire: func() (crypto.Signer, error) { return nil, errors.New("denied") }},
	}
	addr, cleanup := startTestAgent(t, ids)
	defer cleanup()

	c := dialAgent(t, addr)
	keys, err := c.List()
	if err != nil || len(keys) != 2 {
		t.Fatalf("list: %v / %d", err, len(keys))
	}
	for _, k := range keys {
		if _, err := c.Sign(k, []byte("payload")); err == nil {
			t.Fatalf("expected sign with %q to fail", k.Comment)
		}
	}
}

func TestPublicKeyCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "ssh-public-keys.json")
	cache, err := LoadPublicKeyCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := cache.Blob("ssh/github"); ok {
		t.Fatal("empty cache returned a key")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := cache.Put("ssh/github", Identity{Comment: "my laptop", Signer: priv}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file: %v / %v", err, info)
	}
	reloaded, err := LoadPublicKeyCache(path)
	if err != nil {
		t.Fatal(err)
	}
	blob, comment, ok := reloaded.Blob("ssh/github")
	want, _ := PublicBlob(priv)
	if !ok || string(blob) != string(want) || comment != "my laptop" {
		t.Fatalf("reloaded: ok=%v comment=%q", ok, comment)
	}
}
