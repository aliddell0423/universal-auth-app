// Package vaultwrite obtains Pixel approval for overwriting or deleting a
// vault credential.
//
// The desktop creates a broker request of kind "vault_write" whose
// client_nonce is the SHA-256 of Canonical(op). The Pixel's biometric-bound
// signature over that request therefore authorises exactly one write, and
// vault-service verifies it against the pinned Pixel key before applying it.
package vaultwrite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/verify"
)

// Kind is the broker request kind for vault write approvals.
const Kind = "vault_write"

// Write operations.
const (
	OpUpdate = "update"
	OpDelete = "delete"
)

// ErrDenied is returned when the change is denied on the Pixel.
var ErrDenied = errors.New("change was denied on the Pixel")

// Op is the write being authorised. Package is nil for deletes.
type Op struct {
	Op           string
	CredentialID string
	Package      *vaultcrypto.Package
}

// Canonical mirrors vault-service/internal/approval.Canonical;
// testdata/contracts/vault_write_canonical.txt pins the format.
func Canonical(op Op) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "universal-auth:vault-write:v1\n")
	fmt.Fprintf(&b, "op=%s\n", op.Op)
	fmt.Fprintf(&b, "credential_id=%s\n", op.CredentialID)
	p := op.Package
	if p == nil {
		p = &vaultcrypto.Package{}
	}
	fmt.Fprintf(&b, "kind=%s\n", b64url(p.Kind))
	fmt.Fprintf(&b, "resource=%s\n", b64url(p.Resource))
	fmt.Fprintf(&b, "account=%s\n", b64url(p.Account))
	fmt.Fprintf(&b, "ciphertext=%s\n", p.Ciphertext)
	fmt.Fprintf(&b, "cipher_nonce=%s\n", p.CipherNonce)
	fmt.Fprintf(&b, "wrapped_dek=%s\n", p.WrappedDEK)
	fmt.Fprintf(&b, "wrap_nonce=%s\n", p.WrapNonce)
	fmt.Fprintf(&b, "wrap_ephemeral_public_key=%s\n", p.WrapEphemeralPublicKey)
	fmt.Fprintf(&b, "pixel_vault_key_id=%s\n", p.PixelVaultKeyID)
	fmt.Fprintf(&b, "crypto_version=%d\n", p.CryptoVersion)
	return b.Bytes()
}

// Nonce is the client_nonce that authorises op.
func Nonce(op Op) string {
	sum := sha256.Sum256(Canonical(op))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Approve asks the Pixel to approve op and waits for the decision.
// currentResource is the credential's site before the write; the vault
// requires the approval to have been shown for it. message is displayed on
// the Pixel.
func Approve(ctx context.Context, bc *broker.Client, trusted config.TrustedDevice, op Op, currentResource, message string, poll time.Duration) (*broker.Request, error) {
	create := broker.CreateRequest{
		Source:      "universal-auth",
		Kind:        Kind,
		Resource:    currentResource,
		Message:     message,
		ClientNonce: Nonce(op),
	}
	pending, err := bc.CreateRequest(ctx, create, "")
	if err != nil {
		return nil, err
	}
	if err := bc.ValidatePendingResponse(pending, create); err != nil {
		return nil, fmt.Errorf("pending response validation: %w", err)
	}
	intent := verify.PendingIntent{
		RequestID:   pending.ID,
		Challenge:   pending.Challenge,
		ClientNonce: create.ClientNonce,
		Source:      create.Source,
		Kind:        create.Kind,
		Resource:    create.Resource,
		Message:     create.Message,
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for Pixel approval: %w", ctx.Err())
		case <-ticker.C:
			result, err := bc.GetRequest(ctx, pending.ID, "")
			if err != nil {
				return nil, err
			}
			switch result.Status {
			case "pending":
				continue
			case "denied":
				return nil, ErrDenied
			case "approved":
				if err := verify.VerifyApproval(trusted, intent, result); err != nil {
					return nil, err
				}
				return &result, nil
			default:
				return nil, fmt.Errorf("unexpected request status %q", result.Status)
			}
		}
	}
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
