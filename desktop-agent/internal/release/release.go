package release

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

const (
	StatusApproved      = "approved"
	StatusDenied        = "denied"
	StatusPending       = "pending"
	StatusTimeout       = "timeout"
	StatusSecurityError = "security_error"
	StatusReleased      = "released"
)

type Result struct {
	Status    string
	Kind      string
	Resource  string
	Fields    map[string]string
	Error     error
	RequestID string
	TraceID   string
}

// SecureRelease performs the full secure release and returns the decrypted
// fields plus the transaction IDs. resource is the package lookup resource:
// a normalized origin for login packages or a secret name for others.
func SecureRelease(
	ctx context.Context,
	resource string,
	pkg *vaultcrypto.Package,
	ident *identity.Identity,
	pixelVaultKeyID string,
	brokerClient *broker.Client,
	traceID string,
	timeout, poll time.Duration,
) (*Result, error) {
	if pkg.CryptoVersion != vaultcrypto.CryptoVersionV2 && pkg.CryptoVersion != vaultcrypto.CryptoVersionV3 {
		return nil, fmt.Errorf("unsupported package crypto version %d", pkg.CryptoVersion)
	}
	if pkg.Res() != resource {
		return nil, fmt.Errorf("package resource does not match request")
	}
	if pkg.PixelVaultKeyID != pixelVaultKeyID {
		return nil, fmt.Errorf("package pixel vault key id does not match pinned key")
	}
	if err := verifyPackageHash(pkg, vaultcrypto.Hash(pkg)); err != nil {
		return nil, err
	}

	kind := pkg.Kind
	if kind == "" {
		kind = vaultcrypto.KindLogin
	}
	what := "credential"
	if kind != vaultcrypto.KindLogin {
		what = "secret"
	}
	if pkg.Account != "" {
		what += " (" + pkg.Account + ")"
	}

	releasePriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	desktopEphemeralPub, err := publicKeyB64(&releasePriv.PublicKey)
	if err != nil {
		return nil, err
	}

	createReq := broker.CreateRequest{
		Source:      "universal-auth",
		Kind:        "credential_release",
		Resource:    resource,
		Message:     "Release saved " + what + " for " + resource,
		ClientNonce: generateClientNonce(),
	}

	pending, err := brokerClient.CreateRequest(ctx, createReq, traceID)
	if err != nil {
		return nil, err
	}
	if err := brokerClient.ValidatePendingResponse(pending, createReq); err != nil {
		return nil, fmt.Errorf("pending response validation: %w", err)
	}

	canonical := canonicalReleaseRequest(
		2,
		pending.ID,
		pending.Challenge,
		pending.ClientNonce,
		ident.DesktopID(),
		"credential_release",
		resource,
		pkg.CredentialID,
		vaultcrypto.Hash(pkg),
		desktopEphemeralPub,
		pixelVaultKeyID,
	)
	sum := sha256.Sum256(canonical)
	sig, err := ident.Sign(sum[:])
	if err != nil {
		return nil, err
	}

	packageCanonical := string(vaultcrypto.Canonical(pkg))
	attachReq := broker.ReleaseRequest{
		Protocol:               ReleaseProtocolV2,
		DesktopID:              ident.DesktopID(),
		DesktopAlgorithm:       "ECDSA_P256_SHA256",
		DesktopEphemeralPublic: desktopEphemeralPub,
		CredentialPackage:      packageCanonical,
		PackageHash:            vaultcrypto.Hash(pkg),
		DesktopSignature:       sig,
	}
	if _, err := brokerClient.AttachReleaseRequest(ctx, pending.ID, attachReq, traceID); err != nil {
		return nil, err
	}

	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		select {
		case <-pollCtx.Done():
			return nil, fmt.Errorf("timeout")
		case <-ticker.C:
			result, err := brokerClient.GetRequest(ctx, pending.ID, traceID)
			if err != nil {
				return nil, err
			}
			switch result.Status {
			case StatusReleased:
				if result.ReleaseResponse == nil {
					return nil, fmt.Errorf("released but no response present")
				}
				pt, err := decryptReleaseResponse(pkg, result, releasePriv, ident.DesktopID())
				if err != nil {
					return nil, err
				}
				requestTraceID := result.TraceID
				if requestTraceID == "" {
					requestTraceID = traceID
				}
				return &Result{
					Kind:      kind,
					Resource:  resource,
					Fields:    pt.Fields,
					RequestID: result.ID,
					TraceID:   requestTraceID,
				}, nil
			case StatusDenied:
				return nil, fmt.Errorf("denied")
			case StatusPending:
				// continue
			}
		}
	}
}

func generateClientNonce() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decryptReleaseResponse(pkg *vaultcrypto.Package, result broker.Request, releasePriv *ecdsa.PrivateKey, desktopID string) (*vaultcrypto.Plaintext, error) {
	resp := result.ReleaseResponse
	if resp.Protocol != ReleaseProtocolV1 && resp.Protocol != ReleaseProtocolV2 {
		return nil, fmt.Errorf("unsupported release response protocol")
	}
	if resp.CredentialID != pkg.CredentialID {
		return nil, fmt.Errorf("credential id mismatch")
	}
	if resp.PackageHash != vaultcrypto.Hash(pkg) {
		return nil, fmt.Errorf("package hash mismatch in response")
	}
	if resp.PixelVaultKeyID != pkg.PixelVaultKeyID {
		return nil, fmt.Errorf("pixel vault key id mismatch in response")
	}

	version := 1
	if resp.Protocol == ReleaseProtocolV2 {
		version = 2
	}

	pixelEphemeralPub, err := parsePublicKey(resp.PixelEphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("pixel ephemeral public key: %w", err)
	}
	fedoraEphemeralPub, _ := publicKeyB64(&releasePriv.PublicKey)

	secret, err := sharedECDH(releasePriv.D, pixelEphemeralPub)
	if err != nil {
		return nil, err
	}
	salt := transferSalt(
		version,
		result.ID,
		result.Challenge,
		result.ClientNonce,
		desktopID,
		pkg.CredentialID,
		pkg.Res(),
		resp.PackageHash,
		resp.PixelVaultKeyID,
	)
	info := []byte(fmt.Sprintf("universal-auth:release-transfer-key:v%d", version))
	transferKey, err := vaultcrypto.DeriveKey(secret, salt, info, 32)
	if err != nil {
		return nil, err
	}

	encryptedDEK, err := base64.RawURLEncoding.DecodeString(resp.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("encrypted dek: %w", err)
	}
	transferNonce, err := base64.RawURLEncoding.DecodeString(resp.TransferNonce)
	if err != nil {
		return nil, fmt.Errorf("transfer nonce: %w", err)
	}
	aad := transferAAD(
		version,
		result.ID,
		result.Challenge,
		result.ClientNonce,
		desktopID,
		pkg.CredentialID,
		pkg.Res(),
		resp.PackageHash,
		resp.PixelVaultKeyID,
		fedoraEphemeralPub,
		resp.PixelEphemeralPublic,
	)
	dek, err := vaultcrypto.GCMDecrypt(transferKey, encryptedDEK, transferNonce, aad)
	if err != nil {
		return nil, fmt.Errorf("dek decrypt: %w", err)
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("dek length is %d, want 32", len(dek))
	}
	return vaultcrypto.DecryptCredentialWithDEK(pkg, dek)
}
