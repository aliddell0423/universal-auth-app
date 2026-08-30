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

func Lookup(origin string) (Credential, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Credential{}, err
	}
	p := filepath.Join(home, ".config", "universal-auth", "dev-credentials.json")

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Credential{}, ErrNotFound
		}
		return Credential{}, err
	}

	info, err := os.Stat(p)
	if err == nil {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return Credential{}, fmt.Errorf("dev credentials file %s has overly permissive mode %o", p, mode)
		}
	}

	var store map[string]Credential
	if err := json.Unmarshal(data, &store); err != nil {
		return Credential{}, err
	}

	c, ok := store[origin]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return c, nil
}
