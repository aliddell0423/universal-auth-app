package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/auth"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/nm"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
)

const (
	defaultAuthTimeout = 60 * time.Second
	defaultPoll        = 1 * time.Second
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

	vaultToken, err := config.LoadVaultToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load vault token: %v\n", err)
		return outMessage{Status: "error"}
	}
	vaultClient := vault.NewClient(cfg.VaultURL, vaultToken)

	// Metadata-only check before asking the Pixel for approval.
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

	brokerToken, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load broker token: %v\n", err)
		return outMessage{Status: "error"}
	}

	brokerClient := broker.NewClient(cfg.BrokerURL, brokerToken)
	svc := &auth.Service{Client: brokerClient, Config: cfg}

	ctx, cancel = context.WithTimeout(context.Background(), defaultAuthTimeout)
	defer cancel()

	res, err := svc.Authenticate(ctx, auth.Request{
		Source:   auth.DefaultSource(),
		Kind:     "credential_access",
		Resource: req.Origin,
		Message:  "Fill saved login credentials for " + req.Origin,
	}, defaultPoll)

	if res.Status == auth.StatusSecurityError {
		fmt.Fprintf(os.Stderr, "security error: %v\n", err)
		return outMessage{Status: "security_error"}
	}
	if res.Status == auth.StatusTimeout {
		return outMessage{Status: "timeout"}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "authentication: %v\n", err)
		return outMessage{Status: "error"}
	}

	switch res.Status {
	case auth.StatusApproved:
		cred, err := getSecretAfterApproval(cfg.VaultURL, vaultToken, req.Origin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vault retrieval after approval: %v\n", err)
			return outMessage{Status: "error"}
		}
		return outMessage{Status: "approved", Username: cred.Username, Password: cred.Password}
	case auth.StatusDenied:
		return outMessage{Status: "denied"}
	case auth.StatusTimeout:
		return outMessage{Status: "timeout"}
	default:
		return outMessage{Status: "error"}
	}
}

func getSecretAfterApproval(vaultURL, token, origin string) (vault.Credential, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := vault.NewClient(vaultURL, token)
	return c.GetCredential(ctx, origin)
}
