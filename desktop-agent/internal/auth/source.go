package auth

import (
	"os"
	"strings"
)

func DefaultSource() string {
	h, _ := os.Hostname()
	if h == "" {
		return "andrew-fedora"
	}
	h = strings.Split(h, ".")[0]
	return h + "-fedora"
}
