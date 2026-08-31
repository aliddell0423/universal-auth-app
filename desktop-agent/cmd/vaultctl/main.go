package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "add":
		add(os.Args[2:])
	case "list":
		list(os.Args[2:])
	case "delete":
		del(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vaultctl <add|list|delete> [flags]")
}

func add(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	origin := fs.String("origin", "", "credential origin (required)")
	username := fs.String("username", "", "username (required)")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if *origin == "" || *username == "" {
		fmt.Fprintln(os.Stderr, "error: --origin and --username are required")
		os.Exit(1)
	}

	normOrigin, err := vaultcrypto.NormalizeOrigin(*origin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var password string
	if *passwordStdin {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
			os.Exit(1)
		}
		password = strings.TrimRight(line, "\r\n")
	} else {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr)
		password = string(b)
	}
	if password == "" {
		fmt.Fprintln(os.Stderr, "error: password is required")
		os.Exit(1)
	}

	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if cfg.TrustedDevice.VaultPubKey == "" {
		fmt.Fprintln(os.Stderr, "error: Pixel vault key not paired; run authctl pair again")
		os.Exit(1)
	}
	if cfg.VaultURL == "" {
		fmt.Fprintln(os.Stderr, "error: vault_url not configured")
		os.Exit(1)
	}

	vaultDER, err := base64.StdEncoding.DecodeString(cfg.TrustedDevice.VaultPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	pubAny, err := x509.ParsePKIXPublicKey(vaultDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	vaultPub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "error: Pixel vault key is not ECDSA")
		os.Exit(1)
	}

	vaultToken, err := config.LoadVaultToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	vaultClient := vault.NewClient(cfg.VaultURL, vaultToken)

	id, err := generateCredentialID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	pkg, _, err := vaultcrypto.Encrypt(&vaultcrypto.CredentialPlaintext{Username: *username, Password: password}, id, normOrigin, cfg.TrustedDevice.VaultKeyID, vaultPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := vaultClient.CreatePackage(ctx, pkg, ""); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Credential stored: %s -> %s\n", pkg.CredentialID, pkg.Origin)
}

func list(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	vaultToken, err := config.LoadVaultToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	vaultClient := vault.NewClient(cfg.VaultURL, vaultToken)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = vaultClient
	_ = ctx
	// list endpoint not implemented in client for this iteration.
	fmt.Fprintln(os.Stderr, "list not yet implemented")
}

func del(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	id := fs.String("id", "", "credential id (required)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if *id == "" {
		fmt.Fprintln(os.Stderr, "error: --id is required")
		os.Exit(1)
	}
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	vaultToken, err := config.LoadVaultToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	vaultClient := vault.NewClient(cfg.VaultURL, vaultToken)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := vaultClient.DeletePackage(ctx, *id, ""); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Credential deleted: %s\n", *id)
}

func generateCredentialID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
