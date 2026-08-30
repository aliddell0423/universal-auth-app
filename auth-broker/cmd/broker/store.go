package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
)

type ApprovalProof struct {
	DeviceID  string `json:"device_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

type Request struct {
	ID            string         `json:"id"`
	Source        string         `json:"source"`
	Kind          string         `json:"kind"`
	Resource      string         `json:"resource"`
	Message       string         `json:"message"`
	Challenge     string         `json:"challenge"`
	ClientNonce   string         `json:"client_nonce"`
	Status        RequestStatus  `json:"status"`
	CreatedAt     time.Time      `json:"created_at"`
	DecidedAt     *time.Time     `json:"decided_at,omitempty"`
	ApprovalProof *ApprovalProof `json:"approval_proof,omitempty"`
}

type CreateRequest struct {
	Source      string `json:"source"`
	Kind        string `json:"kind"`
	Resource    string `json:"resource"`
	Message     string `json:"message"`
	ClientNonce string `json:"client_nonce"`
}

type Decision struct {
	Decision  string `json:"decision"`
	DeviceID  string `json:"device_id,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type Device struct {
	DeviceID  string
	Name      string
	Algorithm string
	PublicKey *ecdsa.PublicKey
}

var (
	ErrRequestNotFound       = errors.New("request not found")
	ErrInvalidDecision       = errors.New("invalid decision value")
	ErrRequestAlreadyDecided = errors.New("request already decided")
	ErrDeviceAlreadyTrusted  = errors.New("a different device is already trusted")
	ErrDeviceNotFound        = errors.New("device not registered")
	ErrDeviceMismatch        = errors.New("device id does not match the trusted device")
	ErrInvalidSignature      = errors.New("invalid signature")
	ErrMissingClientNonce    = errors.New("client_nonce is required")
)

type Store struct {
	mu     sync.RWMutex
	reqs   map[string]*Request
	device *Device
}

func NewStore() *Store {
	return &Store{reqs: make(map[string]*Request)}
}

func (s *Store) Create(c CreateRequest) (*Request, error) {
	if c.ClientNonce == "" {
		return nil, ErrMissingClientNonce
	}
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	challenge, err := generateChallenge()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	req := &Request{
		ID:          id,
		Source:      c.Source,
		Kind:        c.Kind,
		Resource:    c.Resource,
		Message:     c.Message,
		Challenge:   challenge,
		ClientNonce: c.ClientNonce,
		Status:      StatusPending,
		CreatedAt:   now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs[req.ID] = req
	return req, nil
}

func (s *Store) Get(id string) (*Request, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reqs[id]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

func (s *Store) ListPending() []*Request {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Request, 0)
	for _, r := range s.reqs {
		if r.Status == StatusPending {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out
}

func (s *Store) RegisterDevice(device *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.device != nil {
		if deviceID(s.device.PublicKey) != deviceID(device.PublicKey) {
			return ErrDeviceAlreadyTrusted
		}
		return nil
	}
	s.device = device
	return nil
}

func (s *Store) TrustedDevice() *Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.device == nil {
		return nil
	}
	cp := *s.device
	return &cp
}

func (s *Store) Decide(id, decision string, proof *ApprovalProof) (*Request, error) {
	d := RequestStatus(decision)
	if d != StatusApproved && d != StatusDenied {
		return nil, ErrInvalidDecision
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reqs[id]
	if !ok {
		return nil, ErrRequestNotFound
	}
	if r.Status != StatusPending {
		return nil, ErrRequestAlreadyDecided
	}

	if d == StatusApproved {
		if proof == nil {
			return nil, ErrInvalidSignature
		}
		device := s.device
		if device == nil {
			return nil, ErrDeviceNotFound
		}
		if proof.DeviceID != device.DeviceID {
			return nil, ErrDeviceMismatch
		}
		payload := buildSigningPayload(r, "approved")
		hash := sha256.Sum256(payload)
		sig, err := base64.StdEncoding.DecodeString(proof.Signature)
		if err != nil {
			return nil, ErrInvalidSignature
		}
		if !ecdsa.VerifyASN1(device.PublicKey, hash[:], sig) {
			return nil, ErrInvalidSignature
		}
	}

	now := time.Now().UTC()
	r.Status = d
	r.DecidedAt = &now
	if d == StatusApproved && proof != nil {
		r.ApprovalProof = proof
	}
	cp := *r
	return &cp, nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func deviceID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
