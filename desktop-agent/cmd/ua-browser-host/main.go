package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/apierror"
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
	Status          string `json:"status"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	Code            string `json:"code,omitempty"`
	Stage           string `json:"stage,omitempty"`
	Error           string `json:"error,omitempty"`
	TraceID         string `json:"trace_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	Retryable       bool   `json:"retryable"`
	Action          string `json:"action,omitempty"`
	HostVersion     string `json:"host_version,omitempty"`
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	ConfigLoaded    bool   `json:"config_loaded,omitempty"`
	VaultConfigured bool   `json:"vault_configured,omitempty"`
	PixelPaired     bool   `json:"pixel_paired,omitempty"`
}

func main() {
	var req inMessage
	if err := nm.ReadMessage(os.Stdin, &req); err != nil {
		fmt.Fprintf(os.Stderr, "read native message: %v\n", err)
		resp := outMessage{
			Status:  "error",
			Code:    "UA-BROWSER-003",
			Stage:   "browser.native_read",
			Error:   "Failed to read native message.",
			Action:  "Check the native host logs.",
			TraceID: generateTraceID(),
		}
		_ = nm.WriteMessage(os.Stdout, resp)
		os.Exit(1)
	}

	resp := handle(req)
	if err := nm.WriteMessage(os.Stdout, resp); err != nil {
		fmt.Fprintf(os.Stderr, "write native message: %v\n", err)
		os.Exit(1)
	}
}

func handle(req inMessage) outMessage {
	traceID := generateTraceID()

	if req.Type == "diagnose" {
		return diagnose(traceID)
	}
	if req.Type != "get_credential" || req.Origin == "" {
		return fail(traceID, "UA-BROWSER-002", "browser.validate", "Invalid native message type or missing origin.", "Check the browser extension JSON.", false)
	}

	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load config: %v\n", traceID, err)
		return fail(traceID, "UA-CONFIG-001", "config.load", "Failed to load local configuration.", "Run 'authctl doctor'.", false)
	}
	if cfg.VaultURL == "" {
		return fail(traceID, "UA-CONFIG-002", "config.vault_url", "vault_url is not configured.", "Run 'authctl pair'.", false)
	}
	if cfg.BrokerURL == "" {
		return fail(traceID, "UA-CONFIG-003", "config.broker_url", "broker_url is not configured.", "Run 'authctl pair'.", false)
	}
	if cfg.TrustedDevice.VaultKeyID == "" {
		return fail(traceID, "UA-CONFIG-004", "config.pixel_vault", "Pixel vault key is not paired.", "Run 'authctl pair'.", false)
	}

	vaultToken, err := config.LoadVaultToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load vault token: %v\n", traceID, err)
		return fail(traceID, "UA-CONFIG-005", "config.vault_token", "Failed to load vault token.", "Run 'authctl pair'.", false)
	}
	vaultClient := vault.NewClient(cfg.VaultURL, vaultToken)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	exists, err := vaultClient.CredentialExists(ctx, req.Origin, traceID)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] vault exists check: %v\n", traceID, err)
		return fromError(traceID, err)
	}
	if !exists {
		return fail(traceID, "UA-VAULT-002", "vault.exists", "No saved credential for this origin.", "Use 'vaultctl add' to store one.", false)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	pkg, err := vaultClient.GetPackage(ctx, req.Origin, traceID)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] vault package: %v\n", traceID, err)
		return fromError(traceID, err)
	}

	ident, err := identity.LoadOrCreate("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load identity: %v\n", traceID, err)
		return fail(traceID, "UA-CONFIG-006", "identity.load", "Failed to load desktop identity.", "Run 'authctl doctor'.", false)
	}

	brokerToken, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load broker token: %v\n", traceID, err)
		return fail(traceID, "UA-CONFIG-007", "config.broker_token", "Failed to load broker token.", "Run 'authctl pair'.", false)
	}
	brokerClient := broker.NewClient(cfg.BrokerURL, brokerToken)

	ctx, cancel = context.WithTimeout(context.Background(), defaultReleaseTimeout)
	defer cancel()
	pt, err := release.SecureRelease(ctx, req.Origin, pkg, ident, cfg.TrustedDevice.VaultKeyID, brokerClient, traceID, defaultReleaseTimeout, defaultPoll)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] secure release: %v\n", traceID, err)
		if err.Error() == "denied" {
			return fail(traceID, "UA-RELEASE-003", "release.denied", "Credential release was denied on the Pixel.", "", false)
		}
		if err.Error() == "timeout" {
			return fail(traceID, "UA-RELEASE-002", "release.timeout", "Credential release timed out waiting for Pixel approval.", "Try again.", true)
		}
		return fromError(traceID, err)
	}
	return outMessage{
		Status:   "approved",
		Username: pt.Username,
		Password: pt.Password,
		TraceID:  traceID,
	}
}

func diagnose(traceID string) outMessage {
	cfg, err := config.Load("")
	if err != nil {
		return fail(traceID, "UA-CONFIG-001", "diagnose.config", "Failed to load local configuration.", "Run 'authctl doctor'.", false)
	}

	// No secret values, only configuration presence.
	return outMessage{
		Status:          "ok",
		Code:            "UA-BROWSER-000",
		Stage:           "diagnose",
		TraceID:         traceID,
		Retryable:       false,
		HostVersion:     "0.2.0",
		ProtocolVersion: 2,
		ConfigLoaded:    true,
		VaultConfigured: cfg.VaultURL != "" && cfg.TrustedDevice.VaultKeyID != "",
		PixelPaired:     cfg.TrustedDevice.VaultKeyID != "",
	}
}

func fromError(traceID string, err error) outMessage {
	var apiErr *apierror.Error
	if errors.As(err, &apiErr) {
		return outMessage{
			Status:    "error",
			Code:      apiErr.Code,
			Stage:     apiErr.Stage,
			Error:     apiErr.Message,
			TraceID:   apiErr.TraceID,
			RequestID: apiErr.RequestID,
			Retryable: apiErr.Retryable,
			Action:    apiErr.Action,
		}
	}
	return fail(traceID, "UA-BROWSER-001", "browser.unknown", err.Error(), "Check the Browser Console and run 'authctl doctor'.", false)
}

func fail(traceID, code, stage, msg, action string, retryable bool) outMessage {
	return outMessage{
		Status:    "error",
		Code:      code,
		Stage:     stage,
		Error:     msg,
		TraceID:   traceID,
		Retryable: retryable,
		Action:    action,
	}
}

func generateTraceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func validateVaultKeyID(pub, wantID string) error {
	der, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return err
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}
	_, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("not ECDSA")
	}
	sum := sha256.Sum256(der)
	got := fmt.Sprintf("%x", sum[:])
	if got != wantID {
		return fmt.Errorf("vault key id mismatch")
	}
	return nil
}
