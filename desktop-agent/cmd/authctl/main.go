package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/auth"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
)

const (
	exitApproved        = 0
	exitDenied          = 2
	exitTimeout         = 3
	exitSecurityFailure = 4
	exitError           = 5
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitError)
	}
	switch os.Args[1] {
	case "pair":
		pair(os.Args[2:])
	case "desktop-register":
		desktopRegister(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "usage: authctl <pair|desktop-register|request|inspect> [flags]")
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
	token, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	client := broker.NewClient(*brokerURL, token)
	td, err := client.GetTrustedDevice(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	if err := validateTrustedDevice(td, *expectedID); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY ERROR: %v\n", err)
		os.Exit(exitSecurityFailure)
	}

	cfg := &config.Config{
		BrokerURL: *brokerURL,
		TrustedDevice: config.TrustedDevice{
			DeviceID:    td.DeviceID,
			Name:        td.Name,
			Algorithm:   td.Algorithm,
			PublicKey:   td.PublicKey,
			VaultKeyID:  td.VaultKeyID,
			VaultAlgo:   td.VaultAlgorithm,
			VaultPubKey: td.VaultPublicKey,
		},
	}
	if err := cfg.Save(config.DefaultPath()); err != nil {
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
	if td.VaultAlgorithm != "ECDH_P256_HKDF_SHA256" {
		return fmt.Errorf("unsupported vault algorithm %s", td.VaultAlgorithm)
	}
	vaultDER, err := base64.StdEncoding.DecodeString(td.VaultPublicKey)
	if err != nil {
		return fmt.Errorf("vault public key is not valid base64")
	}
	vaultPubAny, err := x509.ParsePKIXPublicKey(vaultDER)
	if err != nil {
		return fmt.Errorf("vault public key is not valid PKIX")
	}
	vaultPub, ok := vaultPubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("vault public key is not ECDSA")
	}
	if vaultPub.Curve != elliptic.P256() {
		return fmt.Errorf("vault public key is not P-256")
	}
	vaultSum := sha256.Sum256(vaultDER)
	if hex.EncodeToString(vaultSum[:]) != td.VaultKeyID {
		return fmt.Errorf("calculated vault fingerprint does not match vault_key_id")
	}
	return nil
}

func desktopRegister(args []string) {
	fs := flag.NewFlagSet("desktop-register", flag.ExitOnError)
	name := fs.String("name", "Fedora Desktop", "desktop display name")
	brokerURL := fs.String("broker", "http://192.168.1.167:8080", "broker base URL")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	ident, err := identity.LoadOrCreate("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	token, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	client := broker.NewClient(*brokerURL, token)
	if err := client.RegisterDesktop(ctx, broker.TrustedDesktop{
		DesktopID: ident.DesktopID(),
		Name:      *name,
		Algorithm: "ECDSA_P256_SHA256",
		PublicKey: ident.PublicKey(),
	}, ""); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	fmt.Printf("Desktop identity: %s\n", *name)
	fmt.Printf("Fingerprint:\n%s\n", ident.DesktopID())
}

func request(args []string) {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	source := fs.String("source", auth.DefaultSource(), "requesting source identity")
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

	token, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	client := broker.NewClient(cfg.BrokerURL, token)
	svc := &auth.Service{Client: client, Config: cfg}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	pollCtx, pollCancel := context.WithTimeout(ctx, *timeout)
	defer pollCancel()

	fmt.Println("Creating request...")
	fmt.Println("Waiting for Pixel approval...")

	res, err := svc.Authenticate(pollCtx, auth.Request{
		Source:   *source,
		Kind:     *kind,
		Resource: *resource,
		Message:  *message,
	}, *poll)

	if res.Status == auth.StatusSecurityError {
		fmt.Fprintf(os.Stderr, "SECURITY ERROR:\nBroker reported approval but Pixel signature verification failed: %v\n", err)
		os.Exit(exitSecurityFailure)
	}
	if res.Status == auth.StatusTimeout {
		fmt.Println("TIMEOUT")
		os.Exit(exitTimeout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	switch res.Status {
	case auth.StatusApproved:
		fmt.Println("APPROVED")
		fmt.Println("Pixel signature verified.")
		os.Exit(exitApproved)
	case auth.StatusDenied:
		fmt.Println("DENIED")
		os.Exit(exitDenied)
	default:
		fmt.Fprintf(os.Stderr, "error: unexpected status %s\n", res.Status)
		os.Exit(exitError)
	}
}

func inspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	fmt.Printf("Broker: %s\n", cfg.BrokerURL)
	fmt.Printf("Trusted device: %s\n", cfg.TrustedDevice.Name)
	fmt.Printf("Device ID: %s\n", cfg.TrustedDevice.DeviceID)
	fmt.Printf("Algorithm: %s\n", cfg.TrustedDevice.Algorithm)
}
