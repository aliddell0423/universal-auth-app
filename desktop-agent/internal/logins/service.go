// Package logins implements saved-login operations shared by vaultctl and the
// browser native host: matching a page to stored logins, release, save,
// update and delete.
package logins

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/release"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultwrite"
)

// ErrNotOffered means a credential is not a login offered on the page.
var ErrNotOffered = errors.New("that saved login is not offered on this site")

// ErrExists means the site already has a login with that account label.
type ErrExists struct{ CredentialID string }

func (e *ErrExists) Error() string { return "a login for this site and account already exists" }

// Service bundles the clients needed for login operations.
type Service struct {
	Cfg     *config.Config
	Vault   *vault.Client
	Broker  *broker.Client
	Ident   *identity.Identity
	Aliases *AliasStore
	// Timeout bounds each Pixel approval wait.
	Timeout time.Duration
	Poll    time.Duration
}

// Load builds a Service from the local configuration.
func Load() (*Service, error) {
	cfg, err := config.Load("")
	if err != nil {
		return nil, err
	}
	if cfg.VaultURL == "" || cfg.BrokerURL == "" || cfg.TrustedDevice.VaultPubKey == "" {
		return nil, errors.New("vault, broker or Pixel pairing is not configured; run 'authctl doctor'")
	}
	vt, err := config.LoadVaultToken()
	if err != nil {
		return nil, err
	}
	bt, err := config.LoadBrokerToken()
	if err != nil {
		return nil, err
	}
	ident, err := identity.LoadOrCreate("")
	if err != nil {
		return nil, err
	}
	aliases, err := LoadAliases(AliasesPath())
	if err != nil {
		return nil, err
	}
	return &Service{
		Cfg: cfg, Vault: vault.NewClient(cfg.VaultURL, vt), Broker: broker.NewClient(cfg.BrokerURL, bt),
		Ident: ident, Aliases: aliases, Timeout: 90 * time.Second, Poll: time.Second,
	}, nil
}

// Matches returns the stored logins offered on origin, best match first.
func (s *Service) Matches(ctx context.Context, origin, traceID string) ([]Match, error) {
	all, err := s.Vault.List(ctx, traceID)
	if err != nil {
		return nil, err
	}
	return MatchLogins(origin, all, s.Aliases.Aliases)
}

// ReleaseOffered releases credential id after checking it is offered on
// origin, so a page can only obtain logins that belong to it.
func (s *Service) ReleaseOffered(ctx context.Context, origin, id, traceID string) (*release.Result, *vaultcrypto.Package, error) {
	matches, err := s.Matches(ctx, origin, traceID)
	if err != nil {
		return nil, nil, err
	}
	if !slices.ContainsFunc(matches, func(m Match) bool { return m.CredentialID == id }) {
		return nil, nil, ErrNotOffered
	}
	return s.Release(ctx, id, traceID)
}

// Release releases credential id after Pixel approval.
func (s *Service) Release(ctx context.Context, id, traceID string) (*release.Result, *vaultcrypto.Package, error) {
	pkg, err := s.Vault.GetPackageByID(ctx, id, traceID)
	if err != nil {
		return nil, nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	res, err := release.SecureRelease(rctx, pkg.Res(), pkg, s.Ident, s.Cfg.TrustedDevice.VaultKeyID, s.Broker, traceID, s.Timeout, s.Poll)
	if err != nil {
		return nil, nil, err
	}
	return res, pkg, nil
}

// Save stores a new credential. It needs no approval: encryption only uses
// the Pixel's public key. An existing (kind, resource, account) returns
// *ErrExists.
func (s *Service) Save(ctx context.Context, kind, resource, account string, fields map[string]string, traceID string) (*vaultcrypto.Package, error) {
	resource, err := vaultcrypto.NormalizeResource(kind, resource)
	if err != nil {
		return nil, err
	}
	if id, err := s.existing(ctx, kind, resource, account, traceID); err != nil {
		return nil, err
	} else if id != "" {
		return nil, &ErrExists{CredentialID: id}
	}
	id, err := newCredentialID()
	if err != nil {
		return nil, err
	}
	pkg, err := s.encrypt(kind, resource, account, id, fields)
	if err != nil {
		return nil, err
	}
	if err := s.Vault.CreatePackage(ctx, pkg, traceID); err != nil {
		return nil, err
	}
	return pkg, nil
}

// Update replaces credential id with fields, under newResource (empty keeps
// the current one) and account. It waits for Pixel approval of this exact
// change.
func (s *Service) Update(ctx context.Context, id, newResource, account string, fields map[string]string, traceID string) (*vaultcrypto.Package, error) {
	cur, err := s.Vault.GetPackageByID(ctx, id, traceID)
	if err != nil {
		return nil, err
	}
	kind := cur.Kind
	if kind == "" {
		kind = vaultcrypto.KindLogin
	}
	resource := cur.Res()
	if newResource != "" {
		if resource, err = vaultcrypto.NormalizeResource(kind, newResource); err != nil {
			return nil, err
		}
	}
	if other, err := s.existing(ctx, kind, resource, account, traceID); err != nil {
		return nil, err
	} else if other != "" && other != id {
		return nil, &ErrExists{CredentialID: other}
	}
	pkg, err := s.encrypt(kind, resource, account, id, fields)
	if err != nil {
		return nil, err
	}
	msg := describe("Update", resource, account, cur.Res())
	if err := s.approveAndReplace(ctx, id, pkg, cur.Res(), msg, traceID); err != nil {
		return nil, err
	}
	return pkg, nil
}

// Relabel changes only the account label, keeping the encrypted payload, so
// no release is needed. It waits for Pixel approval.
func (s *Service) Relabel(ctx context.Context, id, account, traceID string) error {
	cur, err := s.Vault.GetPackageByID(ctx, id, traceID)
	if err != nil {
		return err
	}
	if cur.CryptoVersion != vaultcrypto.CryptoVersionV3 {
		return errors.New("this entry predates account labels; edit it with a new password instead")
	}
	if other, err := s.existing(ctx, cur.Kind, cur.Resource, account, traceID); err != nil {
		return err
	} else if other != "" && other != id {
		return &ErrExists{CredentialID: other}
	}
	next := *cur
	next.Account = account
	return s.approveAndReplace(ctx, id, &next, cur.Res(), describe("Rename account on", cur.Res(), account, ""), traceID)
}

// Delete removes credential id after Pixel approval.
func (s *Service) Delete(ctx context.Context, id, traceID string) error {
	cur, err := s.Vault.GetPackageByID(ctx, id, traceID)
	if err != nil {
		return err
	}
	op := vaultwrite.Op{Op: vaultwrite.OpDelete, CredentialID: id}
	actx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	appr, err := vaultwrite.Approve(actx, s.Broker, s.Cfg.TrustedDevice, op, cur.Res(), describe("Delete", cur.Res(), cur.Account, ""), s.Poll)
	if err != nil {
		return err
	}
	return s.Vault.DeletePackage(ctx, id, appr, traceID)
}

func (s *Service) approveAndReplace(ctx context.Context, id string, pkg *vaultcrypto.Package, currentResource, msg, traceID string) error {
	op := vaultwrite.Op{Op: vaultwrite.OpUpdate, CredentialID: id, Package: pkg}
	actx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	appr, err := vaultwrite.Approve(actx, s.Broker, s.Cfg.TrustedDevice, op, currentResource, msg, s.Poll)
	if err != nil {
		return err
	}
	return s.Vault.ReplacePackage(ctx, id, pkg, appr, traceID)
}

func (s *Service) existing(ctx context.Context, kind, resource, account, traceID string) (string, error) {
	items, err := s.Vault.ListResource(ctx, resource, kind, traceID)
	if err != nil {
		return "", err
	}
	for _, m := range items {
		if m.Account == account {
			return m.CredentialID, nil
		}
	}
	return "", nil
}

func (s *Service) encrypt(kind, resource, account, id string, fields map[string]string) (*vaultcrypto.Package, error) {
	pub, err := PixelVaultPub(s.Cfg)
	if err != nil {
		return nil, err
	}
	pkg, _, err := vaultcrypto.Encrypt(fields, kind, resource, id, s.Cfg.TrustedDevice.VaultKeyID, pub)
	if err != nil {
		return nil, err
	}
	pkg.Account = account
	return pkg, nil
}

// describe builds the message shown on the Pixel for a write.
func describe(verb, resource, account, from string) string {
	msg := verb + " saved login for " + resource
	if account != "" {
		msg += " (" + account + ")"
	}
	if from != "" && from != resource {
		msg += ", moved from " + from
	}
	return msg
}

// PixelVaultPub parses the pinned Pixel vault public key.
func PixelVaultPub(cfg *config.Config) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(cfg.TrustedDevice.VaultPubKey)
	if err != nil {
		return nil, err
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Pixel vault key is not ECDSA")
	}
	return pub, nil
}

func newCredentialID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
