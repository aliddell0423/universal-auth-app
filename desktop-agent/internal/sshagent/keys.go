package sshagent

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Field names used by ssh_key vault packages.
const (
	FieldPrivateKey = "private_key"
	FieldPassphrase = "passphrase"
	FieldComment    = "comment"
)

// IdentityFromFields builds an agent identity from the released fields of an
// ssh_key package. private_key holds a PEM or OpenSSH private key; passphrase
// is required only when that key is encrypted. name is the fallback comment.
func IdentityFromFields(name string, fields map[string]string) (Identity, error) {
	pemBytes := []byte(fields[FieldPrivateKey])
	if len(pemBytes) == 0 {
		return Identity{}, fmt.Errorf("%s: missing %s field", name, FieldPrivateKey)
	}
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		pass := fields[FieldPassphrase]
		if pass == "" {
			return Identity{}, fmt.Errorf("%s: key is encrypted and no %s field is stored", name, FieldPassphrase)
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(pass))
	}
	if err != nil {
		return Identity{}, fmt.Errorf("%s: parse private key: %w", name, err)
	}
	signer, ok := raw.(crypto.Signer)
	if !ok {
		return Identity{}, fmt.Errorf("%s: unsupported private key type %T", name, raw)
	}
	comment := fields[FieldComment]
	if comment == "" {
		comment = name
	}
	return Identity{Comment: comment, Signer: signer}, nil
}

// PublicKeyCache maps ssh_key resource names to authorized_keys-format public
// keys. It lets the agent advertise identities without releasing the private
// keys. The file holds public keys only.
type PublicKeyCache struct {
	path string
	keys map[string]string
}

// LoadPublicKeyCache reads the cache at path; a missing file is an empty cache.
func LoadPublicKeyCache(path string) (*PublicKeyCache, error) {
	c := &PublicKeyCache{path: path, keys: map[string]string{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &c.keys); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Blob returns the wire-format public key and comment cached for resource.
func (c *PublicKeyCache) Blob(resource string) (blob []byte, comment string, ok bool) {
	line, found := c.keys[resource]
	if !found {
		return nil, "", false
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, "", false
	}
	return pub.Marshal(), comment, true
}

// Put records the public key of id under resource and saves the cache.
func (c *PublicKeyCache) Put(resource string, id Identity) error {
	blob := id.Blob
	if len(blob) == 0 {
		var err error
		if blob, err = PublicBlob(id.Signer); err != nil {
			return err
		}
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if id.Comment != "" {
		line += " " + strings.Join(strings.Fields(id.Comment), " ")
	}
	c.keys[resource] = line
	data, err := json.MarshalIndent(c.keys, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.path, append(data, '\n'), 0o600)
}
