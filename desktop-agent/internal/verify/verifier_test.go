package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/protocol"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func deviceIDFromKey(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func signRequest(t *testing.T, priv *ecdsa.PrivateKey, intent PendingIntent) string {
	t.Helper()
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
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func makeTrusted(t *testing.T, pub *ecdsa.PublicKey) config.TrustedDevice {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return config.TrustedDevice{
		DeviceID:  deviceIDFromKey(t, pub),
		Name:      "Pixel 10",
		Algorithm: "ECDSA_P256_SHA256",
		PublicKey: base64.StdEncoding.EncodeToString(der),
	}
}

func baseIntent() PendingIntent {
	return PendingIntent{
		RequestID:   "0123456789abcdef",
		Challenge:   "dGVzdC1jaGFsbGVuZ2U",
		ClientNonce: "dGVzdC1jbGllbnQtbm9uY2U",
		Source:      "andrew-fedora",
		Kind:        "test",
		Resource:    "development",
		Message:     "Please authenticate",
	}
}

func baseRequest(proof *broker.ApprovalProof) broker.Request {
	return broker.Request{
		ID:            "0123456789abcdef",
		Source:        "andrew-fedora",
		Kind:          "test",
		Resource:      "development",
		Message:       "Please authenticate",
		Challenge:     "dGVzdC1jaGFsbGVuZ2U",
		ClientNonce:   "dGVzdC1jbGllbnQtbm9uY2U",
		Status:        "approved",
		ApprovalProof: proof,
	}
}

func TestVerifyValidApproval(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	proof := &broker.ApprovalProof{
		DeviceID:  trusted.DeviceID,
		Algorithm: "ECDSA_P256_SHA256",
		Signature: signRequest(t, priv, intent),
	}
	result := baseRequest(proof)
	if err := VerifyApproval(trusted, intent, result); err != nil {
		t.Fatalf("expected approval to verify, got: %v", err)
	}
}

func TestVerifyNotApproved(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	result := baseRequest(nil)
	result.Status = "pending"
	if err := VerifyApproval(trusted, intent, result); err != ErrNotApproved {
		t.Fatalf("expected ErrNotApproved, got: %v", err)
	}
}

func TestVerifyMissingProof(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	result := baseRequest(nil)
	if err := VerifyApproval(trusted, intent, result); err != ErrMissingProof {
		t.Fatalf("expected ErrMissingProof, got: %v", err)
	}
}

func TestVerifyWrongDeviceID(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	proof := &broker.ApprovalProof{
		DeviceID:  "wrong",
		Algorithm: "ECDSA_P256_SHA256",
		Signature: signRequest(t, priv, intent),
	}
	result := baseRequest(proof)
	if err := VerifyApproval(trusted, intent, result); err != ErrDeviceMismatch {
		t.Fatalf("expected ErrDeviceMismatch, got: %v", err)
	}
}

func TestVerifyWrongAlgorithm(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	proof := &broker.ApprovalProof{
		DeviceID:  trusted.DeviceID,
		Algorithm: "ECDSA_P384_SHA384",
		Signature: signRequest(t, priv, intent),
	}
	result := baseRequest(proof)
	if err := VerifyApproval(trusted, intent, result); err != ErrAlgorithmMismatch {
		t.Fatalf("expected ErrAlgorithmMismatch, got: %v", err)
	}
}

func TestVerifyTamperedFields(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	base := baseIntent()
	proof := &broker.ApprovalProof{
		DeviceID:  trusted.DeviceID,
		Algorithm: "ECDSA_P256_SHA256",
		Signature: signRequest(t, priv, base),
	}

	cases := []struct {
		name   string
		mutate func(*PendingIntent, *broker.Request)
		want   error
	}{
		{
			name: "source",
			mutate: func(i *PendingIntent, _ *broker.Request) {
				i.Source = "other"
			},
			want: ErrInvalidSignature,
		},
		{
			name: "kind",
			mutate: func(i *PendingIntent, _ *broker.Request) {
				i.Kind = "other"
			},
			want: ErrInvalidSignature,
		},
		{
			name: "resource",
			mutate: func(i *PendingIntent, _ *broker.Request) {
				i.Resource = "other"
			},
			want: ErrInvalidSignature,
		},
		{
			name: "message",
			mutate: func(i *PendingIntent, _ *broker.Request) {
				i.Message = "other"
			},
			want: ErrInvalidSignature,
		},
		{
			name: "request id",
			mutate: func(_ *PendingIntent, r *broker.Request) {
				r.ID = "other"
			},
			want: ErrRequestIDMismatch,
		},
		{
			name: "challenge",
			mutate: func(_ *PendingIntent, r *broker.Request) {
				r.Challenge = "other"
			},
			want: ErrChallengeMismatch,
		},
		{
			name: "client nonce",
			mutate: func(_ *PendingIntent, r *broker.Request) {
				r.ClientNonce = "other"
			},
			want: ErrClientNonceMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := base
			result := baseRequest(proof)
			tc.mutate(&intent, &result)
			if err := VerifyApproval(trusted, intent, result); err != tc.want {
				t.Fatalf("expected %v, got: %v", tc.want, err)
			}
		})
	}
}

func TestVerifyCorruptedSignature(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	proof := &broker.ApprovalProof{
		DeviceID:  trusted.DeviceID,
		Algorithm: "ECDSA_P256_SHA256",
		Signature: "c2lnbmF0dXJl",
	}
	result := baseRequest(proof)
	if err := VerifyApproval(trusted, intent, result); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifyOtherKey(t *testing.T) {
	priv := generateTestKey(t)
	other := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	proof := &broker.ApprovalProof{
		DeviceID:  trusted.DeviceID,
		Algorithm: "ECDSA_P256_SHA256",
		Signature: signRequest(t, other, intent),
	}
	result := baseRequest(proof)
	if err := VerifyApproval(trusted, intent, result); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifyReplayAcrossRequests(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intentA := baseIntent()
	intentA.ClientNonce = "Y2xpZW50LW5vbmNlLWE"
	intentB := baseIntent()
	intentB.ClientNonce = "Y2xpZW50LW5vbmNlLWI"

	proofA := &broker.ApprovalProof{
		DeviceID:  trusted.DeviceID,
		Algorithm: "ECDSA_P256_SHA256",
		Signature: signRequest(t, priv, intentA),
	}
	resultB := baseRequest(proofA)
	resultB.ID = intentB.RequestID
	resultB.Challenge = intentB.Challenge
	resultB.ClientNonce = intentB.ClientNonce

	if err := VerifyApproval(trusted, intentB, resultB); err != ErrInvalidSignature {
		t.Fatalf("expected replay to fail with ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifyForgedApprovedWithoutProof(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	intent := baseIntent()
	result := baseRequest(nil)
	if err := VerifyApproval(trusted, intent, result); err != ErrMissingProof {
		t.Fatalf("expected ErrMissingProof, got: %v", err)
	}
}

func TestVerifyCorruptedPublicKeyDeviceID(t *testing.T) {
	priv := generateTestKey(t)
	trusted := makeTrusted(t, &priv.PublicKey)
	trusted.DeviceID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	intent := baseIntent()
	proof := &broker.ApprovalProof{
		DeviceID:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Algorithm: "ECDSA_P256_SHA256",
		Signature: signRequest(t, priv, intent),
	}
	result := baseRequest(proof)
	if err := VerifyApproval(trusted, intent, result); err != ErrDeviceMismatch {
		t.Fatalf("expected ErrDeviceMismatch, got: %v", err)
	}
}
