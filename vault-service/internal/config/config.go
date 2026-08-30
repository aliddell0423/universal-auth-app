package config

import (
	"encoding/base64"
	"fmt"
	"os"
)

type Config struct {
	Token  string
	KEK    []byte
	Addr   string
	DBPath string
}

func Load() (*Config, error) {
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is required")
	}

	kekB64 := os.Getenv("VAULT_KEK")
	if kekB64 == "" {
		return nil, fmt.Errorf("VAULT_KEK is required")
	}
	kek, err := base64.StdEncoding.DecodeString(kekB64)
	if err != nil {
		return nil, fmt.Errorf("VAULT_KEK is not valid base64: %w", err)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("VAULT_KEK must decode to 32 bytes, got %d", len(kek))
	}

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	db := os.Getenv("VAULT_DB_PATH")
	if db == "" {
		db = "/data/vault.db"
	}

	return &Config{
		Token:  token,
		KEK:    kek,
		Addr:   addr,
		DBPath: db,
	}, nil
}
