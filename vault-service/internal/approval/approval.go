// Package approval verifies Pixel-signed approvals for vault writes.
//
// Overwriting or deleting a credential needs a broker request of kind
// "vault_write" that the Pixel approved with its biometric-bound signing key.
// The desktop sets the request's client_nonce to a digest of the exact write
// (see Canonical), so a signature authorises one specific operation. The
// vault checks the signature against the pinned Pixel approval key itself;
// it does not trust the broker or the vault bearer token for this.
package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"vault-service/internal/model"
)

// Kind is the broker request kind used for vault write approvals.
const Kind = "vault_write"

// Write operations.
const (
	OpUpdate = "update"
	OpDelete = "delete"
)

// Proof is the Pixel's signature as returned by the broker.
type Proof struct {
	DeviceID  string `json:"device_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

// Request is the approved broker request presented as write authorisation.
type Request struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	Kind          string `json:"kind"`
	Resource      string `json:"resource"`
	Message       string `json:"message"`
	Challenge     string `json:"challenge"`
	ClientNonce   string `json:"client_nonce"`
	Status        string `json:"status"`
	ApprovalProof *Proof `json:"approval_proof"`
}

// Op describes the write being authorised. Package is nil for deletes.
type Op struct {
	Op           string
	CredentialID string
	Package      *model.CredentialPackageInput
}

var (
	ErrNotConfigured = errors.New("vault write approvals are not configured (VAULT_APPROVER_PUBLIC_KEY)")
	ErrMissing       = errors.New("write approval is required")
	ErrNotApproved   = errors.New("write approval request is not approved")
	ErrWrongKind     = errors.New("approval request is not a vault_write request")
	ErrDevice        = errors.New("approval was not signed by the trusted Pixel")
	ErrNonce         = errors.New("approval does not authorise this exact write")
	ErrResource      = errors.New("approval was shown for a different site")
	ErrSignature     = errors.New("approval signature is invalid")
)

// Canonical is the byte string whose SHA-256 digest becomes the broker
// request's client_nonce. desktop-agent/internal/vaultwrite builds the same
// bytes; testdata/contracts/vault_write_canonical.txt pins the format.
func Canonical(op Op) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "universal-auth:vault-write:v1\n")
	fmt.Fprintf(&b, "op=%s\n", op.Op)
	fmt.Fprintf(&b, "credential_id=%s\n", op.CredentialID)
	p := op.Package
	if p == nil {
		p = &model.CredentialPackageInput{}
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

// Nonce returns the client_nonce that authorises op.
func Nonce(op Op) string {
	sum := sha256.Sum256(Canonical(op))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Verifier checks approvals against the pinned Pixel approval public key.
type Verifier struct {
	pub      *ecdsa.PublicKey
	deviceID string
}

// NewVerifier parses a standard-Base64 SPKI P-256 public key. An empty key
// returns a nil Verifier, which rejects every write.
func NewVerifier(spkiB64 string) (*Verifier, error) {
	if spkiB64 == "" {
		return nil, nil
	}
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return nil, fmt.Errorf("approver public key is not valid base64: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("approver public key is not valid SPKI: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("approver public key is not ECDSA")
	}
	sum := sha256.Sum256(der)
	return &Verifier{pub: pub, deviceID: hex.EncodeToString(sum[:])}, nil
}

// Verify checks that req is a Pixel-approved authorisation for op, and that
// the Pixel was shown currentResource (the credential's site before the write).
func (v *Verifier) Verify(req *Request, op Op, currentResource string) error {
	if v == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrMissing
	}
	if req.Status != "approved" || req.ApprovalProof == nil {
		return ErrNotApproved
	}
	if req.Kind != Kind {
		return ErrWrongKind
	}
	proof := req.ApprovalProof
	if proof.DeviceID != v.deviceID || proof.Algorithm != "ECDSA_P256_SHA256" {
		return ErrDevice
	}
	if req.ClientNonce != Nonce(op) {
		return ErrNonce
	}
	if req.Resource != currentResource {
		return ErrResource
	}
	sig, err := base64.StdEncoding.DecodeString(proof.Signature)
	if err != nil {
		return ErrSignature
	}
	digest := sha256.Sum256(signingPayload(req))
	if !ecdsa.VerifyASN1(v.pub, digest[:], sig) {
		return ErrSignature
	}
	return nil
}

// signingPayload mirrors auth-broker/cmd/broker/payload.go and the Pixel's
// SigningPayload.kt for an approved decision.
func signingPayload(req *Request) []byte {
	var b bytes.Buffer
	fmt.Fprint(&b, "universal-auth:v2\n")
	fmt.Fprintf(&b, "request_id=%s\n", b64url(req.ID))
	fmt.Fprintf(&b, "challenge=%s\n", req.Challenge)
	fmt.Fprintf(&b, "client_nonce=%s\n", req.ClientNonce)
	fmt.Fprintf(&b, "decision=%s\n", b64url("approved"))
	fmt.Fprintf(&b, "source=%s\n", b64url(req.Source))
	fmt.Fprintf(&b, "kind=%s\n", b64url(req.Kind))
	fmt.Fprintf(&b, "resource=%s\n", b64url(req.Resource))
	fmt.Fprintf(&b, "message=%s\n", b64url(req.Message))
	return b.Bytes()
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
