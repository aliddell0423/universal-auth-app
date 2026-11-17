package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/release"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/sshagent"
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
	case "get":
		get(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, `usage: vaultctl <add|get|list|delete> [flags]

  add      --kind login|secret|ssh_key --origin URL | --name NAME
           login:   --username U [--password-stdin | prompt]
           others:  --field KEY=VALUE ... [--field-file KEY=PATH]
  get      --origin URL | --name NAME [--kind KIND] [--field KEY] [--json]
           Releases the secret after Pixel approval and prints it.
  list     Lists stored credentials (metadata only, no secrets).
  delete   --id CREDENTIAL_ID`)
}

type fieldFlags []string

func (f *fieldFlags) String() string { return strings.Join(*f, ",") }
func (f *fieldFlags) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func parseFields(pairs fieldFlags, files fieldFlags) (map[string]string, error) {
	fields := make(map[string]string)
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --field %q (want KEY=VALUE)", p)
		}
		fields[k] = v
	}
	for _, p := range files {
		k, path, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid --field-file %q (want KEY=PATH)", p)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		fields[k] = strings.TrimRight(string(b), "\r\n")
	}
	return fields, nil
}

func loadVaultClient() (*config.Config, *vault.Client, error) {
	cfg, err := config.Load("")
	if err != nil {
		return nil, nil, err
	}
	if cfg.TrustedDevice.VaultPubKey == "" {
		return nil, nil, fmt.Errorf("Pixel vault key not paired; run authctl pair again")
	}
	if cfg.VaultURL == "" {
		return nil, nil, fmt.Errorf("vault_url not configured")
	}
	token, err := config.LoadVaultToken()
	if err != nil {
		return nil, nil, err
	}
	return cfg, vault.NewClient(cfg.VaultURL, token), nil
}

func pixelVaultPub(cfg *config.Config) (*ecdsa.PublicKey, error) {
	vaultDER, err := base64.StdEncoding.DecodeString(cfg.TrustedDevice.VaultPubKey)
	if err != nil {
		return nil, err
	}
	pubAny, err := x509.ParsePKIXPublicKey(vaultDER)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Pixel vault key is not ECDSA")
	}
	return pub, nil
}

func add(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	kind := fs.String("kind", vaultcrypto.KindLogin, "package kind: login, secret or ssh_key")
	origin := fs.String("origin", "", "login origin, e.g. https://github.com")
	name := fs.String("name", "", "secret name, e.g. api-keys/github")
	username := fs.String("username", "", "username for login kind")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	var fieldPairs, fieldFiles fieldFlags
	fs.Var(&fieldPairs, "field", "KEY=VALUE field (repeatable)")
	fs.Var(&fieldFiles, "field-file", "KEY=PATH read field value from file (repeatable)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if !vaultcrypto.ValidKind(*kind) {
		fmt.Fprintf(os.Stderr, "error: unsupported kind %q\n", *kind)
		os.Exit(1)
	}

	resource, err := vaultcrypto.NormalizeResource(*kind, resourceArg(*kind, *origin, *name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fields := map[string]string{}
	if *kind == vaultcrypto.KindLogin {
		if *username == "" {
			fmt.Fprintln(os.Stderr, "error: --username is required for login kind")
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
		fields["username"] = *username
		fields["password"] = password
	} else {
		f, err := parseFields(fieldPairs, fieldFiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(f) == 0 {
			fmt.Fprintln(os.Stderr, "error: at least one --field or --field-file is required")
			os.Exit(1)
		}
		fields = f
	}

	// Reject unusable SSH keys before storing them, and keep the public half
	// so ua-ssh-agent can offer the key without releasing it.
	var sshIdentity *sshagent.Identity
	if *kind == vaultcrypto.KindSSHKey {
		id, err := sshagent.IdentityFromFields(resource, fields)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		sshIdentity = &id
	}

	cfg, vaultClient, err := loadVaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	vaultPub, err := pixelVaultPub(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	id, err := generateCredentialID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	pkg, _, err := vaultcrypto.Encrypt(fields, *kind, resource, id, cfg.TrustedDevice.VaultKeyID, vaultPub)
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
	fmt.Printf("Stored %s %s (%s)\n", pkg.Kind, pkg.Resource, pkg.CredentialID)
	if sshIdentity != nil {
		cache, err := sshagent.LoadPublicKeyCache(config.SSHPublicKeysPath())
		if err == nil {
			err = cache.Put(resource, *sshIdentity)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not cache public key (ua-ssh-agent will ask for one approval to learn it): %v\n", err)
		}
	}
}

func resourceArg(kind, origin, name string) string {
	if kind == vaultcrypto.KindLogin {
		return origin
	}
	return name
}

func get(args []string) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	origin := fs.String("origin", "", "login origin")
	name := fs.String("name", "", "secret name")
	kind := fs.String("kind", "", "restrict to this kind when a name is used by several")
	field := fs.String("field", "", "print only this field")
	asJSON := fs.Bool("json", false, "print fields as a JSON object")
	timeout := fs.Duration("timeout", 90*time.Second, "approval timeout")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	resource, err := resolveResource(*origin, *name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cfg, vaultClient, err := loadVaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	pkg, err := vaultClient.GetPackageKind(ctx, resource, *kind, "")
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ident, err := identity.LoadOrCreate("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	brokerToken, err := config.LoadBrokerToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	brokerClient := broker.NewClient(cfg.BrokerURL, brokerToken)

	ctx, cancel = context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := release.SecureRelease(ctx, resource, pkg, ident, cfg.TrustedDevice.VaultKeyID, brokerClient, "", *timeout, time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release failed: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		b, _ := json.Marshal(result.Fields)
		fmt.Println(string(b))
		return
	}
	if *field != "" {
		v, ok := result.Fields[*field]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: field %q not present\n", *field)
			os.Exit(1)
		}
		fmt.Println(v)
		return
	}
	keys := make([]string, 0, len(result.Fields))
	for k := range result.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s=%s\n", k, result.Fields[k])
	}
}

func resolveResource(origin, name string) (string, error) {
	switch {
	case origin != "" && name != "":
		return "", fmt.Errorf("use only one of --origin or --name")
	case origin != "":
		return vaultcrypto.NormalizeOrigin(origin)
	case name != "":
		return vaultcrypto.NormalizeSecretName(name)
	default:
		return "", fmt.Errorf("one of --origin or --name is required")
	}
}

func list(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	_, vaultClient, err := loadVaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	items, err := vaultClient.List(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for _, m := range items {
		fmt.Printf("%-10s %-40s %s (v%d)\n", m.Kind, m.Resource, m.CredentialID, m.CryptoVersion)
	}
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
	_, vaultClient, err := loadVaultClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
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
