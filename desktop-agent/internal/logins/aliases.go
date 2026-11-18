package logins

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

// AliasStore persists "use the logins of resource R on page origin O" links.
// It lives on the desktop, not in the vault, so neither the server nor a web
// page can redirect where a login is offered.
type AliasStore struct {
	path    string
	Aliases map[string][]string // page origin -> stored resources
}

// AliasesPath is the default alias file.
func AliasesPath() string {
	return filepath.Join(filepath.Dir(config.DefaultPath()), "site-aliases.json")
}

// LoadAliases reads path; a missing file is an empty store.
func LoadAliases(path string) (*AliasStore, error) {
	s := &AliasStore{path: path, Aliases: map[string][]string{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.Aliases); err != nil {
		return nil, err
	}
	return s, nil
}

// Link makes logins stored for resource available on origin.
func (s *AliasStore) Link(origin, resource string) error {
	o, err := vaultcrypto.NormalizeOrigin(origin)
	if err != nil {
		return err
	}
	r, err := vaultcrypto.NormalizeOrigin(resource)
	if err != nil {
		return err
	}
	if o == r {
		return errors.New("a site cannot be linked to itself")
	}
	if !slices.Contains(s.Aliases[o], r) {
		s.Aliases[o] = append(s.Aliases[o], r)
	}
	return s.save()
}

// Unlink removes a link; unlinking a missing link is not an error.
func (s *AliasStore) Unlink(origin, resource string) error {
	o, err := vaultcrypto.NormalizeOrigin(origin)
	if err != nil {
		return err
	}
	if n, err := vaultcrypto.NormalizeOrigin(resource); err == nil {
		resource = n
	}
	s.Aliases[o] = slices.DeleteFunc(s.Aliases[o], func(r string) bool { return r == resource })
	if len(s.Aliases[o]) == 0 {
		delete(s.Aliases, o)
	}
	return s.save()
}

func (s *AliasStore) save() error {
	data, err := json.MarshalIndent(s.Aliases, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
