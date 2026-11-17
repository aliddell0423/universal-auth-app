// Package sshagent implements a minimal SSH agent (PROTOCOL.agent) server
// backed by in-memory signers. It is used by ua-ssh-agent to expose vault
// ssh_key secrets to ssh clients.
package sshagent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Agent protocol message types (PROTOCOL.agent).
const (
	msgFailure   = 5
	msgSuccess   = 6
	msgIdentAns  = 12
	msgSignAns   = 14
	msgRemoveAll = 19

	reqIdentities    = 11
	reqSign          = 13
	reqAddIdentity   = 17
	reqRemove        = 18
	reqRemoveAll     = 19
	reqLock          = 22
	reqUnlock        = 23
	reqAddConstraint = 25

	flagRSA_SHA2_256 = 2
	flagRSA_SHA2_512 = 4
)

// Identity is a single agent key. Either Signer is set and the private key
// stays in memory, or Acquire is set and the key is fetched for each
// signature and dropped afterwards; Acquire identities must provide Blob.
type Identity struct {
	Comment string
	Signer  crypto.Signer
	Blob    []byte
	Acquire func() (crypto.Signer, error)
}

// Server is an SSH agent protocol server holding a fixed set of identities.
type Server struct {
	mu         sync.RWMutex
	identities map[string]Identity // keyed by string(blob)
	// acquireMu serialises Acquire calls so only one approval is pending.
	acquireMu sync.Mutex
}

// NewServer builds a Server from identities. Blob is derived from the
// signer's public key when empty.
func NewServer(ids []Identity) (*Server, error) {
	s := &Server{identities: make(map[string]Identity)}
	for _, id := range ids {
		blob := id.Blob
		if len(blob) == 0 {
			if id.Signer == nil {
				return nil, fmt.Errorf("identity %q: no public key", id.Comment)
			}
			var err error
			if blob, err = PublicBlob(id.Signer); err != nil {
				return nil, fmt.Errorf("identity %q: %w", id.Comment, err)
			}
		}
		id.Blob = blob
		s.identities[string(blob)] = id
	}
	return s, nil
}

// PublicBlob returns the SSH wire-format public key of signer.
func PublicBlob(signer crypto.Signer) ([]byte, error) {
	pub, err := publicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return p.Marshal(), nil
}

func publicKeyOf(signer crypto.Signer) (crypto.PublicKey, error) {
	pub := signer.Public()
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported public key type %T", pub)
}

// Identities returns the configured identities (copies).
func (s *Server) Identities() []Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Identity, 0, len(s.identities))
	for _, id := range s.identities {
		out = append(out, id)
	}
	return out
}

// Serve accepts connections on ln until it is closed or ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	for {
		msgType, payload, err := readMessage(conn)
		if err != nil {
			return
		}
		respType, resp := s.dispatch(msgType, payload)
		if err := writeMessage(conn, respType, resp); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(msgType byte, payload []byte) (byte, []byte) {
	switch msgType {
	case reqIdentities:
		return s.answerIdentities()
	case reqSign:
		return s.answerSign(payload)
	case reqRemoveAll:
		s.mu.Lock()
		s.identities = make(map[string]Identity)
		s.mu.Unlock()
		return msgSuccess, nil
	case reqRemove:
		blob, ok := readString(payload)
		if !ok {
			return msgFailure, nil
		}
		s.mu.Lock()
		delete(s.identities, string(blob))
		s.mu.Unlock()
		return msgSuccess, nil
	case reqAddIdentity, reqAddConstraint, reqLock, reqUnlock:
		// Adding keys at runtime is not supported; lock/unlock is a no-op
		// failure since the agent holds no passphrase.
		return msgFailure, nil
	default:
		return msgFailure, nil
	}
}

func (s *Server) answerIdentities() (byte, []byte) {
	s.mu.RLock()
	ids := make([]Identity, 0, len(s.identities))
	for _, id := range s.identities {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	out := newWriter()
	putU32(out, uint32(len(ids)))
	for _, id := range ids {
		putString(out, id.Blob)
		comment := id.Comment
		if comment == "" {
			comment = keyTypeName(id.Blob)
		}
		putString(out, []byte(comment))
	}
	return msgIdentAns, out.Bytes()
}

func (s *Server) answerSign(payload []byte) (byte, []byte) {
	r := &reader{b: payload}
	blob, ok := r.string()
	if !ok {
		return msgFailure, nil
	}
	data, ok := r.string()
	if !ok {
		return msgFailure, nil
	}
	flags, ok := r.u32()
	if !ok {
		return msgFailure, nil
	}

	s.mu.RLock()
	id, ok := s.identities[string(blob)]
	s.mu.RUnlock()
	if !ok {
		return msgFailure, nil
	}

	signer := id.Signer
	if signer == nil {
		var err error
		if signer, err = s.acquire(id); err != nil {
			return msgFailure, nil
		}
	}
	sig, err := sign(signer, blob, data, flags)
	if err != nil {
		return msgFailure, nil
	}

	out := newWriter()
	putString(out, sig)
	return msgSignAns, out.Bytes()
}

// acquire fetches the private key for id and checks it is the key that was
// advertised, so a swapped vault entry cannot sign under another identity.
func (s *Server) acquire(id Identity) (crypto.Signer, error) {
	if id.Acquire == nil {
		return nil, errors.New("identity has no key source")
	}
	s.acquireMu.Lock()
	defer s.acquireMu.Unlock()
	signer, err := id.Acquire()
	if err != nil {
		return nil, err
	}
	blob, err := PublicBlob(signer)
	if err != nil {
		return nil, err
	}
	if string(blob) != string(id.Blob) {
		return nil, errors.New("released key does not match the advertised public key")
	}
	return signer, nil
}

// sign produces the SSH wire-format signature for the given key blob.
func sign(signer crypto.Signer, blob, data []byte, flags uint32) ([]byte, error) {
	alg := keyTypeName(blob)
	switch alg {
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", "ssh-dss":
		return signRSA(signer, data, flags)
	case "ssh-ed25519":
		return signEd25519(signer, data)
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return signECDSA(signer, blob, data)
	default:
		return nil, fmt.Errorf("unsupported key type %q", alg)
	}
}

func signRSA(signer crypto.Signer, data []byte, flags uint32) ([]byte, error) {
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, errors.New("not an RSA signer")
	}
	var h crypto.Hash
	var alg string
	switch flags & (flagRSA_SHA2_256 | flagRSA_SHA2_512) {
	case flagRSA_SHA2_512:
		h, alg = crypto.SHA512, "rsa-sha2-512"
	case flagRSA_SHA2_256:
		h, alg = crypto.SHA256, "rsa-sha2-256"
	default:
		h, alg = crypto.SHA1, "ssh-rsa"
	}
	hasher := hashFor(h)()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	sig, err := signer.Sign(rand.Reader, digest, h)
	if err != nil {
		return nil, err
	}
	out := newWriter()
	putString(out, []byte(alg))
	putString(out, sig)
	return out.Bytes(), nil
}

func signEd25519(signer crypto.Signer, data []byte) ([]byte, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); !ok {
		return nil, errors.New("not an ed25519 signer")
	}
	sig, err := signer.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	out := newWriter()
	putString(out, []byte("ssh-ed25519"))
	putString(out, sig)
	return out.Bytes(), nil
}

func signECDSA(signer crypto.Signer, blob, data []byte) ([]byte, error) {
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		return nil, errors.New("not an ECDSA signer")
	}
	alg := keyTypeName(blob)
	h := crypto.SHA256
	switch alg {
	case "ecdsa-sha2-nistp384":
		h = crypto.SHA384
	case "ecdsa-sha2-nistp521":
		h = crypto.SHA512
	}
	hasher := hashFor(h)()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	der, err := signer.Sign(rand.Reader, digest, h)
	if err != nil {
		return nil, err
	}
	var ecsig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &ecsig); err != nil {
		return nil, fmt.Errorf("ecdsa signature parse: %w", err)
	}

	out := newWriter()
	putString(out, []byte(alg))
	inner := newWriter()
	putString(inner, mpint(ecsig.R))
	putString(inner, mpint(ecsig.S))
	putString(out, inner.Bytes())
	return out.Bytes(), nil
}

func hashFor(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New
	case crypto.SHA384:
		return sha512.New384
	case crypto.SHA512:
		return sha512.New
	default:
		return sha256.New
	}
}

// keyTypeName extracts the algorithm name (first string) from a public key blob.
func keyTypeName(blob []byte) string {
	r := &reader{b: blob}
	s, ok := r.string()
	if !ok {
		return ""
	}
	return string(s)
}

// mpint encodes a big.Int as an SSH mpint.
func mpint(v *big.Int) []byte {
	if v == nil {
		return nil
	}
	b := v.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// --- wire codec ---

type writer struct{ b []byte }

func newWriter() *writer        { return &writer{} }
func (w *writer) Bytes() []byte { return w.b }

func putU32(w *writer, v uint32) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	w.b = append(w.b, tmp[:]...)
}

func putString(w *writer, b []byte) {
	putU32(w, uint32(len(b)))
	w.b = append(w.b, b...)
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) u32() (uint32, bool) {
	if len(r.b)-r.off < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, true
}

func (r *reader) string() ([]byte, bool) {
	n, ok := r.u32()
	if !ok || uint64(n) > uint64(len(r.b)-r.off) {
		return nil, false
	}
	v := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return v, true
}

func readString(b []byte) ([]byte, bool) {
	r := &reader{b: b}
	return r.string()
}

func readMessage(conn net.Conn) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 1 || n > 1<<20 {
		return 0, nil, errors.New("agent message too large")
	}
	// n counts the type byte already consumed in hdr[4].
	payload := make([]byte, n-1)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return hdr[4], payload, nil
}

func writeMessage(conn net.Conn, msgType byte, payload []byte) error {
	body := make([]byte, 0, len(payload)+1)
	body = append(body, msgType)
	body = append(body, payload...)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}
