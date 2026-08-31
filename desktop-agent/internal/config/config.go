package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type TrustedDevice struct {
	DeviceID    string `json:"device_id"`
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	VaultKeyID  string `json:"vault_key_id"`
	VaultAlgo   string `json:"vault_algorithm"`
	VaultPubKey string `json:"vault_public_key"`
}

const CurrentConfigVersion = 1

type Config struct {
	ConfigVersion int           `json:"config_version"`
	BrokerURL     string        `json:"broker_url"`
	VaultURL      string        `json:"vault_url"`
	TrustedDevice TrustedDevice `json:"trusted_device"`
}

func DefaultPath() string {
	if p := os.Getenv("UNIVERSAL_AUTH_CONFIG"); p != "" {
		return p
	}
	home := os.Getenv("HOME")
	if home == "" {
		u, err := userHome()
		if err != nil {
			panic(fmt.Sprintf("cannot determine home directory: %v", err))
		}
		home = u
	}
	return filepath.Join(home, ".config", "universal-auth", "config.json")
}

func userHome() (string, error) {
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return u, nil
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	c.ConfigVersion = CurrentConfigVersion
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
