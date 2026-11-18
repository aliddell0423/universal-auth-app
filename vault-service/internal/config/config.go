package config

import (
	"fmt"
	"os"
)

type Config struct {
	Token  string
	Addr   string
	DBPath string
	// ApproverPublicKey is the Pixel approval key (standard-Base64 SPKI) that
	// must sign overwrites and deletes. Empty disables those operations.
	ApproverPublicKey string
}

func Load() (*Config, error) {
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is required")
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
		Token:             token,
		Addr:              addr,
		DBPath:            db,
		ApproverPublicKey: os.Getenv("VAULT_APPROVER_PUBLIC_KEY"),
	}, nil
}
