package model

import (
	"fmt"
	"net/url"
	"strings"
)

func NormalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid origin: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("path not allowed in origin")
	}
	if u.RawQuery != "" {
		return "", fmt.Errorf("query not allowed in origin")
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("fragment not allowed in origin")
	}
	if u.User != nil {
		return "", fmt.Errorf("userinfo not allowed in origin")
	}

	host := u.Hostname()
	port := u.Port()
	if port != "" {
		// Drop default ports so https://example.com and https://example.com:443 match.
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			port = ""
		}
	}

	if port != "" {
		return u.Scheme + "://" + host + ":" + port, nil
	}
	return u.Scheme + "://" + host, nil
}

// Package kinds mirrored from the desktop-agent vaultcrypto package.
const (
	KindLogin  = "login"
	KindSecret = "secret"
	KindSSHKey = "ssh_key"
)

// NormalizeSecretName validates and normalizes a secret resource name.
func NormalizeSecretName(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("secret name is required")
	}
	if len(raw) > 128 {
		return "", fmt.Errorf("secret name too long")
	}
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "/") || strings.HasSuffix(raw, "/") ||
		strings.Contains(raw, "//") || strings.Contains(raw, "..") {
		return "", fmt.Errorf("invalid secret name %q", raw)
	}
	for i, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '/':
			if i == 0 || i == len(raw)-1 {
				return "", fmt.Errorf("invalid secret name %q", raw)
			}
		default:
			return "", fmt.Errorf("invalid character %q in secret name", r)
		}
	}
	return raw, nil
}

// NormalizeResource validates a v3 package resource for the given kind.
func NormalizeResource(kind, raw string) (string, error) {
	switch kind {
	case KindLogin:
		return NormalizeOrigin(raw)
	case KindSecret, KindSSHKey:
		return NormalizeSecretName(raw)
	default:
		return "", fmt.Errorf("unsupported kind %q", kind)
	}
}
