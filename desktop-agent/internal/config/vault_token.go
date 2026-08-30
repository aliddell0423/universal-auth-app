package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const envVaultToken = "VAULT_TOKEN"

func VaultTokenPath() string {
	if p := os.Getenv("UNIVERSAL_AUTH_VAULT_TOKEN"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(DefaultPath()), "vault.token")
}

func LoadVaultToken() (string, error) {
	tok := os.Getenv(envVaultToken)
	if tok != "" {
		return tok, nil
	}
	p := VaultTokenPath()
	data, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("vault token not found: set %s or create %s", envVaultToken, p)
	}
	info, err := os.Stat(p)
	if err == nil {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return "", fmt.Errorf("vault token file %s has overly permissive mode %o", p, mode)
		}
	}
	return strings.TrimSpace(string(data)), nil
}
