package config

import "path/filepath"

// SSHPublicKeysPath is the local cache of public keys for ssh_key secrets.
func SSHPublicKeysPath() string {
	return filepath.Join(filepath.Dir(DefaultPath()), "ssh-public-keys.json")
}
