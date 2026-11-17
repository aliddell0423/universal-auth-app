package release

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
)

const ReleaseProtocolV1 = "universal-auth:secure-release:v1"
const ReleaseProtocolV2 = "universal-auth:secure-release:v2"

// canonicalReleaseRequest builds the signed payload the Pixel verifies.
// v2 uses resource (origin for logins, name for secrets); v1 uses origin.
func canonicalReleaseRequest(
	version int,
	requestID,
	challenge,
	clientNonce,
	desktopID,
	kind,
	resource,
	credentialID,
	packageHash,
	desktopEphemeralPub,
	pixelVaultKeyID string,
) []byte {
	var buf bytes.Buffer
	if version == 2 {
		fmt.Fprint(&buf, "universal-auth:secure-release-request:v2\n")
	} else {
		fmt.Fprint(&buf, "universal-auth:secure-release-request:v1\n")
	}
	fmt.Fprintf(&buf, "request_id=%s\n", b64urlutf8(requestID))
	fmt.Fprintf(&buf, "challenge=%s\n", challenge)
	fmt.Fprintf(&buf, "client_nonce=%s\n", clientNonce)
	fmt.Fprintf(&buf, "desktop_id=%s\n", desktopID)
	fmt.Fprintf(&buf, "kind=%s\n", b64urlutf8(kind))
	if version == 2 {
		fmt.Fprintf(&buf, "resource=%s\n", b64urlutf8(resource))
	} else {
		fmt.Fprintf(&buf, "origin=%s\n", b64urlutf8(resource))
	}
	fmt.Fprintf(&buf, "credential_id=%s\n", b64urlutf8(credentialID))
	fmt.Fprintf(&buf, "package_hash=%s\n", packageHash)
	fmt.Fprintf(&buf, "desktop_ephemeral_public_key=%s\n", desktopEphemeralPub)
	fmt.Fprintf(&buf, "pixel_vault_key_id=%s\n", pixelVaultKeyID)
	return buf.Bytes()
}

func b64urlutf8(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func transferSalt(
	version int,
	requestID,
	challenge,
	clientNonce,
	desktopID,
	credentialID,
	resource,
	packageHash,
	pixelVaultKeyID string,
) []byte {
	resourceKey := "origin"
	if version == 2 {
		resourceKey = "resource"
	}
	msg := fmt.Sprintf("universal-auth:release-transfer-salt:v%d\n"+
		"request_id=%s\n"+
		"challenge=%s\n"+
		"client_nonce=%s\n"+
		"desktop_id=%s\n"+
		"credential_id=%s\n"+
		"%s=%s\n"+
		"package_hash=%s\n"+
		"pixel_vault_key_id=%s\n",
		version, requestID, challenge, clientNonce, desktopID, credentialID, resourceKey, resource, packageHash, pixelVaultKeyID)
	sum := sha256.Sum256([]byte(msg))
	return sum[:]
}

func transferAAD(
	version int,
	requestID,
	challenge,
	clientNonce,
	desktopID,
	credentialID,
	resource,
	packageHash,
	pixelVaultKeyID,
	fedoraEphemeralPub,
	pixelEphemeralPub string,
) []byte {
	resourceKey := "origin"
	if version == 2 {
		resourceKey = "resource"
	}
	return []byte(fmt.Sprintf("universal-auth:release-dek:v%d\n"+
		"request_id=%s\n"+
		"challenge=%s\n"+
		"client_nonce=%s\n"+
		"desktop_id=%s\n"+
		"credential_id=%s\n"+
		"%s=%s\n"+
		"package_hash=%s\n"+
		"pixel_vault_key_id=%s\n"+
		"fedora_ephemeral_public_key=%s\n"+
		"pixel_ephemeral_public_key=%s\n",
		version, requestID, challenge, clientNonce, desktopID, credentialID, resourceKey, resource, packageHash, pixelVaultKeyID, fedoraEphemeralPub, pixelEphemeralPub))
}

func deriveTransferKey(secret, salt, info []byte) ([]byte, error) {
	return vaultcrypto.DeriveKey(secret, salt, info, 32)
}

func sharedECDH(localPrivScalar *big.Int, peerPub *ecdsa.PublicKey) ([]byte, error) {
	priv, err := ecdh.P256().NewPrivateKey(pad32(localPrivScalar.Bytes()))
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(elliptic.Marshal(peerPub.Curve, peerPub.X, peerPub.Y))
	if err != nil {
		return nil, err
	}
	return priv.ECDH(peer)
}

func pad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func publicKeyDER(pub *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

func publicKeyB64(pub *ecdsa.PublicKey) (string, error) {
	der, err := publicKeyDER(pub)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}

func parsePublicKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("not P-256")
	}
	return pub, nil
}

func verifyPackageHash(pkg *vaultcrypto.Package, want string) error {
	got := vaultcrypto.Hash(pkg)
	if got != want {
		return fmt.Errorf("package hash mismatch")
	}
	return nil
}
