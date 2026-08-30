package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrNotFound = errors.New("credential not found for origin")

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "universal-auth", "dev-credentials.json")
}

type Store struct {
	raw map[string]json.RawMessage
}

// Open reads the credential store and checks that it is not group- or world-readable.
// It only loads the origin keys and raw entries, not the decrypted values.
func Open(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	info, err := os.Stat(path)
	if err == nil {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return nil, fmt.Errorf("dev credentials file %s has overly permissive mode %o", path, mode)
		}
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &Store{raw: raw}, nil
}

func (s *Store) Has(origin string) bool {
	_, ok := s.raw[origin]
	return ok
}

func (s *Store) Get(origin string) (Credential, error) {
	v, ok := s.raw[origin]
	if !ok {
		return Credential{}, ErrNotFound
	}

	var c Credential
	if err := json.Unmarshal(v, &c); err != nil {
		return Credential{}, err
	}
	return c, nil
}
