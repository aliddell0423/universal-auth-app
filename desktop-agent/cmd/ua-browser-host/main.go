package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/auth"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/credentials"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/nm"
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

	// Open the store but only check for key presence before approval.
	// The actual username/password is loaded only after the Pixel signature
	// has been verified locally.
	store, err := credentials.Open(credentials.DefaultPath())
	if err != nil {
		if err == credentials.ErrNotFound {
			return outMessage{Status: "not_found"}
		}
		fmt.Fprintf(os.Stderr, "open credentials: %v\n", err)
		return outMessage{Status: "error"}
	}
	if !store.Has(req.Origin) {
		return outMessage{Status: "not_found"}
	}

	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return outMessage{Status: "error"}
	}

	token, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load broker token: %v\n", err)
		return outMessage{Status: "error"}
	}

	client := broker.NewClient(cfg.BrokerURL, token)
	svc := &auth.Service{Client: client, Config: cfg}

	ctx, cancel := context.WithTimeout(context.Background(), defaultAuthTimeout)
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
		cred, err := store.Get(req.Origin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read credential after approval: %v\n", err)
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
