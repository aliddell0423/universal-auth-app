package main

import (
	"crypto/rand"
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

type Request struct {
	ID        string        `json:"id"`
	Source    string        `json:"source"`
	Kind      string        `json:"kind"`
	Resource  string        `json:"resource"`
	Message   string        `json:"message"`
	Status    RequestStatus `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	DecidedAt *time.Time    `json:"decided_at,omitempty"`
}

type CreateRequest struct {
	Source   string `json:"source"`
	Kind     string `json:"kind"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
}

type Decision struct {
	Decision string `json:"decision"`
}

var (
	ErrRequestNotFound     = errors.New("request not found")
	ErrInvalidDecision     = errors.New("invalid decision value")
	ErrRequestAlreadyDecided = errors.New("request already decided")
)

type Store struct {
	mu   sync.RWMutex
	reqs map[string]*Request
}

func NewStore() *Store {
	return &Store{reqs: make(map[string]*Request)}
}

func (s *Store) Create(source, kind, resource, message string) (*Request, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	req := &Request{
		ID:        id,
		Source:    source,
		Kind:      kind,
		Resource:  resource,
		Message:   message,
		Status:    StatusPending,
		CreatedAt: now,
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

func (s *Store) Decide(id, decision string) (*Request, error) {
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
	now := time.Now().UTC()
	r.Status = d
	r.DecidedAt = &now
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
