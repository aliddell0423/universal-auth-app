package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/protocol"
)

type PendingIntent struct {
	RequestID   string
	Challenge   string
	ClientNonce string
	Source      string
	Kind        string
	Resource    string
	Message     string
}

var (
	ErrNotApproved         = errors.New("request is not approved")
	ErrMissingProof        = errors.New("approval proof is missing")
	ErrDeviceMismatch      = errors.New("approval proof device_id does not match the pinned device")
	ErrAlgorithmMismatch   = errors.New("approval proof algorithm is not supported")
	ErrRequestIDMismatch   = errors.New("returned request id does not match the local intent")
	ErrChallengeMismatch   = errors.New("returned challenge does not match the local intent")
	ErrClientNonceMismatch = errors.New("returned client_nonce does not match the local intent")
	ErrInvalidSignature    = errors.New("signature verification failed")
	ErrInvalidPublicKey    = errors.New("pinned public key is invalid")
)

func VerifyApproval(trusted config.TrustedDevice, intent PendingIntent, result broker.Request) error {
	if result.Status != "approved" {
		return ErrNotApproved
	}
	if result.ApprovalProof == nil {
		return ErrMissingProof
	}
	proof := result.ApprovalProof

	if proof.DeviceID != trusted.DeviceID {
		return ErrDeviceMismatch
	}
	if proof.Algorithm != "ECDSA_P256_SHA256" {
		return ErrAlgorithmMismatch
	}
	if result.ID != intent.RequestID {
		return ErrRequestIDMismatch
	}
	if result.Challenge != intent.Challenge {
		return ErrChallengeMismatch
	}
	if result.ClientNonce != intent.ClientNonce {
		return ErrClientNonceMismatch
	}

	pub, err := decodePublicKey(trusted.PublicKey)
	if err != nil {
		return err
	}
	if deviceID(pub) != trusted.DeviceID {
		return ErrDeviceMismatch
	}

	payload := protocol.BuildSigningPayload(
		intent.RequestID,
		intent.Challenge,
		intent.ClientNonce,
		intent.Source,
		intent.Kind,
		intent.Resource,
		intent.Message,
		"approved",
	)
	hash := sha256.Sum256(payload)
	sig, err := base64.StdEncoding.DecodeString(proof.Signature)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, hash[:], sig) {
		return ErrInvalidSignature
	}
	return nil
}

func decodePublicKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid PKIX: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("public key is not P-256")
	}
	return pub, nil
}

func deviceID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
