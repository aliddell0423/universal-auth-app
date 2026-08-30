package model

import (
	"fmt"
	"net/url"
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
