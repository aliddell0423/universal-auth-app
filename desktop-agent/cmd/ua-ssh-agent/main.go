// ua-ssh-agent is an SSH agent backed by ssh_key secrets in the vault.
//
// It never keeps a private key. Identities are advertised from a local cache
// of public keys, and every signature request releases the key through the
// secure release flow (one Pixel approval), signs once, and drops it.
package main

import (
	"context"
	"crypto"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/release"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/sshagent"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

type nameFlags []string

func (n *nameFlags) String() string { return strings.Join(*n, ",") }
func (n *nameFlags) Set(v string) error {
	*n = append(*n, v)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ua-ssh-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var names nameFlags
	flag.Var(&names, "name", "ssh_key secret name to load (repeatable; default: every ssh_key in the vault)")
	socket := flag.String("socket", defaultSocket(), "unix socket path to listen on")
	timeout := flag.Duration("timeout", 90*time.Second, "Pixel approval timeout per key")
	flag.Parse()

	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	if cfg.VaultURL == "" || cfg.BrokerURL == "" || cfg.TrustedDevice.VaultKeyID == "" {
		return errors.New("vault, broker or Pixel pairing is not configured; run 'authctl doctor'")
	}
	vaultToken, err := config.LoadVaultToken()
	if err != nil {
		return err
	}
	brokerToken, err := config.LoadBrokerToken()
	if err != nil {
		return err
	}
	ident, err := identity.LoadOrCreate("")
	if err != nil {
		return err
	}
	vaultClient := vault.NewClient(cfg.VaultURL, vaultToken)
	brokerClient := broker.NewClient(cfg.BrokerURL, brokerToken)

	resources, err := resolveNames(vaultClient, names)
	if err != nil {
		return err
	}
	if len(resources) == 0 {
		return errors.New("no ssh_key secrets found; add one with 'vaultctl add --kind ssh_key --name ssh/<name> --field-file private_key=PATH'")
	}

	// Claim the socket before asking for approvals so a bad path fails fast.
	ln, err := listen(*socket)
	if err != nil {
		return err
	}
	defer os.Remove(*socket)
	defer ln.Close()

	cache, err := sshagent.LoadPublicKeyCache(config.SSHPublicKeysPath())
	if err != nil {
		return err
	}
	acquire := func(res string) func() (crypto.Signer, error) {
		return func() (crypto.Signer, error) {
			fmt.Fprintf(os.Stderr, "%s signature with %s requested: approve on the Pixel...\n", time.Now().Format(time.TimeOnly), res)
			id, err := loadKey(vaultClient, brokerClient, ident, cfg.TrustedDevice.VaultKeyID, res, *timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", res, err)
				return nil, err
			}
			return id.Signer, nil
		}
	}

	var ids []sshagent.Identity
	for _, res := range resources {
		blob, comment, ok := cache.Blob(res)
		if !ok {
			// The public key is only known after one release.
			fmt.Fprintf(os.Stderr, "No cached public key for %s: approve one release on the Pixel to learn it...\n", res)
			id, err := loadKey(vaultClient, brokerClient, ident, cfg.TrustedDevice.VaultKeyID, res, *timeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "skipping %s: %v\n", res, err)
				continue
			}
			if err := cache.Put(res, id); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not cache public key for %s: %v\n", res, err)
			}
			if blob, err = sshagent.PublicBlob(id.Signer); err != nil {
				fmt.Fprintf(os.Stderr, "skipping %s: %v\n", res, err)
				continue
			}
			comment = id.Comment
		}
		if comment == "" {
			comment = res
		}
		ids = append(ids, sshagent.Identity{Comment: comment, Blob: blob, Acquire: acquire(res)})
	}
	if len(ids) == 0 {
		return errors.New("no keys available")
	}
	srv, err := sshagent.NewServer(ids)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "Offering %d key(s) on %s; each use needs a Pixel approval.\n", len(ids), *socket)
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", *socket)
	return srv.Serve(ctx, ln)
}

func defaultSocket() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "ua-ssh-agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("ua-ssh-agent-%d.sock", os.Getuid()))
}

// resolveNames returns the normalized ssh_key resources to load: the names
// given on the command line, or every ssh_key in the vault when none are.
func resolveNames(vaultClient *vault.Client, names []string) ([]string, error) {
	if len(names) > 0 {
		out := make([]string, 0, len(names))
		for _, n := range names {
			norm, err := vaultcrypto.NormalizeSecretName(n)
			if err != nil {
				return nil, err
			}
			out = append(out, norm)
		}
		return out, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	items, err := vaultClient.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range items {
		if m.Kind == vaultcrypto.KindSSHKey {
			out = append(out, m.Resource)
		}
	}
	return out, nil
}

func loadKey(vaultClient *vault.Client, brokerClient *broker.Client, ident *identity.Identity, pixelVaultKeyID, resource string, timeout time.Duration) (sshagent.Identity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	pkg, err := vaultClient.GetPackageKind(ctx, resource, vaultcrypto.KindSSHKey, "")
	cancel()
	if err != nil {
		return sshagent.Identity{}, err
	}
	if pkg.Kind != vaultcrypto.KindSSHKey {
		return sshagent.Identity{}, fmt.Errorf("package kind is %q, want %q", pkg.Kind, vaultcrypto.KindSSHKey)
	}
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := release.SecureRelease(ctx, resource, pkg, ident, pixelVaultKeyID, brokerClient, "", timeout, time.Second)
	if err != nil {
		return sshagent.Identity{}, err
	}
	return sshagent.IdentityFromFields(resource, result.Fields)
}

// listen creates the agent socket with owner-only permissions, replacing a
// stale socket left by a previous run but refusing to displace a live agent.
func listen(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			return nil, fmt.Errorf("an agent is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	return ln, err
}
