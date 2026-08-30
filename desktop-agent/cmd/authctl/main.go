package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/verify"
)

const (
	exitApproved        = 0
	exitDenied          = 2
	exitTimeout         = 3
	exitSecurityFailure = 4
	exitError           = 5
)

const envBrokerToken = "BROKER_TOKEN"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitError)
	}
	switch os.Args[1] {
	case "pair":
		pair(os.Args[2:])
	case "request":
		request(os.Args[2:])
	case "inspect":
		inspect(os.Args[2:])
	default:
		usage()
		os.Exit(exitError)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: authctl <pair|request|inspect> [flags]")
}

func loadToken() (string, error) {
	tok := os.Getenv(envBrokerToken)
	if tok == "" {
		return "", fmt.Errorf("BROKER_TOKEN is required")
	}
	return tok, nil
}

func configPath() string {
	if p := os.Getenv("UNIVERSAL_AUTH_CONFIG"); p != "" {
		return p
	}
	home := os.Getenv("HOME")
	if home == "" {
		u, err := os.UserHomeDir()
		if err == nil {
			home = u
		}
	}
	return filepath.Join(home, ".config", "universal-auth", "config.json")
}

func pair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	brokerURL := fs.String("broker", "http://192.168.1.167:8080", "broker base URL")
	expectedID := fs.String("expected-device-id", "", "expected out-of-band device fingerprint (required)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	if *expectedID == "" {
		fmt.Fprintln(os.Stderr, "error: --expected-device-id is required")
		os.Exit(exitError)
	}
	token, err := loadToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	client := broker.NewClient(*brokerURL, token)
	td, err := client.GetTrustedDevice(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	if err := validateTrustedDevice(td, *expectedID); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY ERROR: %v\n", err)
		os.Exit(exitSecurityFailure)
	}

	cfg := &config.Config{
		BrokerURL:     *brokerURL,
		TrustedDevice: config.TrustedDevice(td),
	}
	if err := cfg.Save(configPath()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	fmt.Printf("Trusted device: %s\n", td.Name)
	fmt.Printf("Algorithm: %s\n", td.Algorithm)
	fmt.Printf("Fingerprint:\n%s\n\n", td.DeviceID)
	fmt.Println("Pixel approval key pinned successfully.")
}

func validateTrustedDevice(td broker.TrustedDevice, expected string) error {
	if td.Algorithm != "ECDSA_P256_SHA256" {
		return fmt.Errorf("unsupported algorithm %s", td.Algorithm)
	}
	der, err := base64.StdEncoding.DecodeString(td.PublicKey)
	if err != nil {
		return fmt.Errorf("public key is not valid base64")
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("public key is not valid PKIX")
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return fmt.Errorf("public key is not P-256")
	}
	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])
	if fingerprint != td.DeviceID {
		return fmt.Errorf("calculated fingerprint does not match broker device_id")
	}
	if fingerprint != expected {
		return fmt.Errorf("calculated fingerprint does not match expected device_id")
	}
	return nil
}

func request(args []string) {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	source := fs.String("source", defaultSource(), "requesting source identity")
	kind := fs.String("kind", "", "request kind (required)")
	resource := fs.String("resource", "", "request resource (required)")
	message := fs.String("message", "", "request message (required)")
	timeout := fs.Duration("timeout", 60*time.Second, "total polling timeout")
	poll := fs.Duration("poll-interval", 1*time.Second, "polling interval")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	if *kind == "" || *resource == "" || *message == "" {
		fmt.Fprintln(os.Stderr, "error: --kind, --resource, and --message are required")
		os.Exit(exitError)
	}

	token, err := loadToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	client := broker.NewClient(cfg.BrokerURL, token)

	clientNonce, err := generateClientNonce()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	createReq := broker.CreateRequest{
		Source:      *source,
		Kind:        *kind,
		Resource:    *resource,
		Message:     *message,
		ClientNonce: clientNonce,
	}
	fmt.Println("Creating request...")
	req, err := client.CreateRequest(ctx, createReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	if err := client.ValidatePendingResponse(req, createReq); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY ERROR: %v\n", err)
		os.Exit(exitSecurityFailure)
	}

	intent := verify.PendingIntent{
		RequestID:   req.ID,
		Challenge:   req.Challenge,
		ClientNonce: clientNonce,
		Source:      *source,
		Kind:        *kind,
		Resource:    *resource,
		Message:     *message,
	}

	fmt.Println("Waiting for Pixel approval...")

	pollCtx, pollCancel := context.WithTimeout(ctx, *timeout)
	defer pollCancel()

	ticker := time.NewTicker(*poll)
	defer ticker.Stop()

	for {
		select {
		case <-pollCtx.Done():
			fmt.Println("TIMEOUT")
			os.Exit(exitTimeout)
		case <-ticker.C:
			result, err := client.GetRequest(ctx, req.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(exitError)
			}
			switch result.Status {
			case "approved":
				if err := verify.VerifyApproval(cfg.TrustedDevice, intent, result); err != nil {
					fmt.Fprintf(os.Stderr, "SECURITY ERROR:\nBroker reported approval but Pixel signature verification failed: %v\n", err)
					os.Exit(exitSecurityFailure)
				}
				fmt.Println("APPROVED")
				fmt.Println("Pixel signature verified.")
				os.Exit(exitApproved)
			case "denied":
				fmt.Println("DENIED")
				os.Exit(exitDenied)
			case "pending":
				// continue waiting
			default:
				fmt.Fprintf(os.Stderr, "error: unexpected status %s\n", result.Status)
				os.Exit(exitError)
			}
		}
	}
}

func inspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	fmt.Printf("Broker: %s\n", cfg.BrokerURL)
	fmt.Printf("Trusted device: %s\n", cfg.TrustedDevice.Name)
	fmt.Printf("Device ID: %s\n", cfg.TrustedDevice.DeviceID)
	fmt.Printf("Algorithm: %s\n", cfg.TrustedDevice.Algorithm)
}

func defaultSource() string {
	h, _ := os.Hostname()
	if h == "" {
		return "andrew-fedora"
	}
	return h + "-fedora"
}

func generateClientNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
