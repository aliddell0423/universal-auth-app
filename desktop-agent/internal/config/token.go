package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const envBrokerToken = "BROKER_TOKEN"

func TokenPath() string {
	if p := os.Getenv("UNIVERSAL_AUTH_TOKEN"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(DefaultPath()), "broker.token")
}

func LoadBrokerToken() (string, error) {
	tok := os.Getenv(envBrokerToken)
	if tok != "" {
		return tok, nil
	}
	p := TokenPath()
	data, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("broker token not found: set %s or create %s", envBrokerToken, p)
	}
	info, err := os.Stat(p)
	if err == nil {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			return "", fmt.Errorf("broker token file %s has overly permissive mode %o", p, mode)
		}
	}
	return strings.TrimSpace(string(data)), nil
}
