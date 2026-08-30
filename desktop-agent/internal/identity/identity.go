package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Identity struct {
	path       string
	privateKey *ecdsa.PrivateKey
	publicDER  []byte
	desktopID  string
}

func DefaultPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".config", "universal-auth", "desktop-identity.pem")
}

// LoadOrCreate loads an existing desktop identity key or generates and stores a new one.
func LoadOrCreate(path string) (*Identity, error) {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err == nil {
		priv, err := parsePEM(data)
		if err != nil {
			return nil, err
		}
		return newIdentity(path, priv), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := storePEM(path, priv); err != nil {
		return nil, err
	}
	return newIdentity(path, priv), nil
}

func newIdentity(path string, priv *ecdsa.PrivateKey) *Identity {
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(der)
	return &Identity{
		path:       path,
		privateKey: priv,
		publicDER:  der,
		desktopID:  hex.EncodeToString(sum[:]),
	}
}

func (id *Identity) PublicKey() string {
	return base64.StdEncoding.EncodeToString(id.publicDER)
}

func (id *Identity) PublicKeyDER() []byte {
	return id.publicDER
}

func (id *Identity) DesktopID() string {
	return id.desktopID
}

func (id *Identity) Sign(digest []byte) (string, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, id.privateKey, digest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (id *Identity) Verify(digest []byte, signature string) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !ecdsa.VerifyASN1(&id.privateKey.PublicKey, digest, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func parsePEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("identity file is not valid PEM")
	}
	if block.Type != "EC PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("identity file is not an ECDSA key")
		}
		return priv, nil
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		if priv.Curve != elliptic.P256() {
			return nil, errors.New("identity key is not P-256")
		}
		return priv, nil
	}
	return nil, errors.New("could not parse identity key")
}

func storePEM(path string, priv *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	data := pem.EncodeToMemory(block)
	return os.WriteFile(path, data, 0o600)
}
