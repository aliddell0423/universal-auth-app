package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/nm"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/release"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
)

const (
	defaultReleaseTimeout = 60 * time.Second
	defaultPoll           = 1 * time.Second
)

type inMessage struct {
	Type   string `json:"type"`
	Origin string `json:"origin"`
}

type outMessage struct {
	Status   string `json:"status"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func main() {
	var req inMessage
	if err := nm.ReadMessage(os.Stdin, &req); err != nil {
		fmt.Fprintf(os.Stderr, "read native message: %v\n", err)
		os.Exit(1)
	}

	resp := handle(req)
	if err := nm.WriteMessage(os.Stdout, resp); err != nil {
		fmt.Fprintf(os.Stderr, "write native message: %v\n", err)
		os.Exit(1)
	}
}

func handle(req inMessage) outMessage {
	if req.Type != "get_credential" || req.Origin == "" {
		return outMessage{Status: "error"}
	}

	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return outMessage{Status: "error"}
	}
	if cfg.VaultURL == "" {
		fmt.Fprintln(os.Stderr, "vault_url is not configured")
		return outMessage{Status: "error"}
	}
	if cfg.TrustedDevice.VaultKeyID == "" {
		fmt.Fprintln(os.Stderr, "pixel vault key is not paired; run authctl pair again")
		return outMessage{Status: "error"}
	}

	vaultToken, err := config.LoadVaultToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load vault token: %v\n", err)
		return outMessage{Status: "error"}
	}
	vaultClient := vault.NewClient(cfg.VaultURL, vaultToken)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	exists, err := vaultClient.CredentialExists(ctx, req.Origin)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault exists check: %v\n", err)
		return outMessage{Status: "error"}
	}
	if !exists {
		return outMessage{Status: "not_found"}
	}

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	pkg, err := vaultClient.GetPackage(ctx, req.Origin)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault package: %v\n", err)
		return outMessage{Status: "error"}
	}

	ident, err := identity.LoadOrCreate("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load identity: %v\n", err)
		return outMessage{Status: "error"}
	}

	brokerToken, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load broker token: %v\n", err)
		return outMessage{Status: "error"}
	}
	brokerClient := broker.NewClient(cfg.BrokerURL, brokerToken)

	ctx, cancel = context.WithTimeout(context.Background(), defaultReleaseTimeout)
	defer cancel()
	pt, err := release.SecureRelease(ctx, req.Origin, pkg, ident, cfg.TrustedDevice.VaultKeyID, brokerClient, defaultReleaseTimeout, defaultPoll)
	if err != nil {
		if err.Error() == "denied" {
			return outMessage{Status: "denied"}
		}
		if err.Error() == "timeout" {
			return outMessage{Status: "timeout"}
		}
		fmt.Fprintf(os.Stderr, "secure release: %v\n", err)
		return outMessage{Status: "security_error"}
	}
	return outMessage{Status: "approved", Username: pt.Username, Password: pt.Password}
}

func validateVaultKeyID(pub string, wantID string) error {
	der, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return err
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}
	p, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not ECDSA")
	}
	_ = p
	sum := sha256.Sum256(der)
	got := fmt.Sprintf("%x", sum[:])
	if got != wantID {
		return fmt.Errorf("vault key id mismatch")
	}
	return nil
}
