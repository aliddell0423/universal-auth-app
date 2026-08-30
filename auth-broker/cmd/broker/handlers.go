package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	maxBodySize      = 64 * 1024
	authHeaderPrefix = "Bearer "
	v1Prefix         = "/v1/"
)

type DeviceRegistration struct {
	DeviceID       string `json:"device_id"`
	Name           string `json:"name"`
	Algorithm      string `json:"algorithm"`
	PublicKey      string `json:"public_key"`
	VaultKeyID     string `json:"vault_key_id"`
	VaultAlgorithm string `json:"vault_algorithm"`
	VaultPublicKey string `json:"vault_public_key"`
}

type DesktopRegistration struct {
	DesktopID string `json:"desktop_id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type TrustedDeviceResponse struct {
	DeviceID       string `json:"device_id"`
	Name           string `json:"name"`
	Algorithm      string `json:"algorithm"`
	PublicKey      string `json:"public_key"`
	VaultKeyID     string `json:"vault_key_id"`
	VaultAlgorithm string `json:"vault_algorithm"`
	VaultPublicKey string `json:"vault_public_key"`
}

type TrustedDesktopResponse struct {
	DesktopID string `json:"desktop_id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

func newServer(store *Store, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/v1/requests/pending", func(w http.ResponseWriter, r *http.Request) { handleListPending(w, r, store) })
	mux.HandleFunc("/v1/requests/", func(w http.ResponseWriter, r *http.Request) { handleRequestByID(w, r, store) })
	mux.HandleFunc("/v1/requests", func(w http.ResponseWriter, r *http.Request) { handleCreate(w, r, store) })
	mux.HandleFunc("/v1/devices/register", func(w http.ResponseWriter, r *http.Request) { handleRegisterDevice(w, r, store) })
	mux.HandleFunc("/v1/devices/trusted", func(w http.ResponseWriter, r *http.Request) { handleGetTrustedDevice(w, r, store) })
	mux.HandleFunc("/v1/desktops", func(w http.ResponseWriter, r *http.Request) { handleDesktops(w, r, store) })
	mux.HandleFunc("/v1/desktops/trusted", func(w http.ResponseWriter, r *http.Request) { handleGetTrustedDesktop(w, r, store) })
	return authMiddleware(mux, token)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleCreate(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var c CreateRequest
	if err := decodeJSON(w, r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "malformed or invalid JSON")
		return
	}
	if c.Source == "" || c.Kind == "" || c.Resource == "" || c.Message == "" || c.ClientNonce == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}
	req, err := store.Create(c)
	if err != nil {
		if errors.Is(err, ErrMissingClientNonce) {
			writeError(w, http.StatusBadRequest, "client_nonce is required")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, req)
}

func handleListPending(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, store.ListPending())
}

func handleRequestByID(w http.ResponseWriter, r *http.Request, store *Store) {
	suffix := strings.TrimPrefix(r.URL.Path, "/v1/requests/")
	if suffix == "" || strings.HasSuffix(suffix, "/") {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	parts := strings.Split(suffix, "/")
	if len(parts) == 1 {
		handleGet(w, r, store, parts[0])
		return
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "decision":
			handleDecision(w, r, store, parts[0])
			return
		case "release-request":
			handleAttachReleaseRequest(w, r, store, parts[0])
			return
		case "release-response":
			handleAttachReleaseResponse(w, r, store, parts[0])
			return
		}
	}
	writeError(w, http.StatusNotFound, "request not found")
}

func handleGet(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	req, ok := store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func handleDecision(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var d Decision
	if err := decodeJSON(w, r, &d); err != nil {
		writeError(w, http.StatusBadRequest, "malformed or invalid JSON")
		return
	}
	if d.Decision != "approved" && d.Decision != "denied" {
		writeError(w, http.StatusBadRequest, "invalid decision value")
		return
	}

	var proof *ApprovalProof
	if d.Decision == "approved" {
		proof = &ApprovalProof{
			DeviceID:  d.DeviceID,
			Algorithm: "ECDSA_P256_SHA256",
			Signature: d.Signature,
		}
	}

	req, err := store.Decide(id, d.Decision, proof)
	if err != nil {
		switch {
		case errors.Is(err, ErrRequestNotFound):
			writeError(w, http.StatusNotFound, "request not found")
		case errors.Is(err, ErrInvalidDecision):
			writeError(w, http.StatusBadRequest, "invalid decision value")
		case errors.Is(err, ErrRequestAlreadyDecided):
			writeError(w, http.StatusConflict, "request already decided")
		case errors.Is(err, ErrDeviceNotFound):
			writeError(w, http.StatusForbidden, "device not registered")
		case errors.Is(err, ErrDeviceMismatch):
			writeError(w, http.StatusForbidden, "device id does not match the trusted device")
		case errors.Is(err, ErrInvalidSignature):
			writeError(w, http.StatusForbidden, "invalid signature")
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func handleRegisterDevice(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var reg DeviceRegistration
	if err := decodeJSON(w, r, &reg); err != nil {
		writeError(w, http.StatusBadRequest, "malformed or invalid JSON")
		return
	}
	if reg.Algorithm != "ECDSA_P256_SHA256" {
		writeError(w, http.StatusBadRequest, "unsupported algorithm")
		return
	}
	if reg.DeviceID == "" || reg.Name == "" || reg.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	pub, err := parseP256PublicKey(reg.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if deviceID(pub) != reg.DeviceID {
		writeError(w, http.StatusBadRequest, "device_id does not match public key")
		return
	}
	if reg.VaultKeyID == "" || reg.VaultAlgorithm == "" || reg.VaultPublicKey == "" {
		writeError(w, http.StatusBadRequest, "missing vault key fields")
		return
	}
	if reg.VaultAlgorithm != "ECDH_P256_HKDF_SHA256" {
		writeError(w, http.StatusBadRequest, "unsupported vault algorithm")
		return
	}
	vaultPub, err := parseP256PublicKey(reg.VaultPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "vault public key: "+err.Error())
		return
	}
	if deviceID(vaultPub) != reg.VaultKeyID {
		writeError(w, http.StatusBadRequest, "vault_key_id does not match vault public key")
		return
	}

	err = store.RegisterDevice(&Device{
		DeviceID:       reg.DeviceID,
		Name:           reg.Name,
		Algorithm:      reg.Algorithm,
		PublicKey:      pub,
		VaultKeyID:     reg.VaultKeyID,
		VaultAlgo:      reg.VaultAlgorithm,
		VaultPublicKey: vaultPub,
	})
	if err != nil {
		if errors.Is(err, ErrDeviceAlreadyTrusted) {
			writeError(w, http.StatusConflict, "a different device is already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleGetTrustedDevice(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	dev := store.TrustedDevice()
	if dev == nil {
		writeError(w, http.StatusNotFound, "no trusted device registered")
		return
	}
	der, err := x509.MarshalPKIXPublicKey(dev.PublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	vaultDER, err := x509.MarshalPKIXPublicKey(dev.VaultPublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, TrustedDeviceResponse{
		DeviceID:       dev.DeviceID,
		Name:           dev.Name,
		Algorithm:      dev.Algorithm,
		PublicKey:      base64.StdEncoding.EncodeToString(der),
		VaultKeyID:     dev.VaultKeyID,
		VaultAlgorithm: dev.VaultAlgo,
		VaultPublicKey: base64.StdEncoding.EncodeToString(vaultDER),
	})
}

func handleDesktops(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var reg DesktopRegistration
	if err := decodeJSON(w, r, &reg); err != nil {
		writeError(w, http.StatusBadRequest, "malformed or invalid JSON")
		return
	}
	if reg.Algorithm != "ECDSA_P256_SHA256" {
		writeError(w, http.StatusBadRequest, "unsupported algorithm")
		return
	}
	if reg.DesktopID == "" || reg.Name == "" || reg.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}
	pub, err := parseP256PublicKey(reg.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if desktopID(pub) != reg.DesktopID {
		writeError(w, http.StatusBadRequest, "desktop_id does not match public key")
		return
	}
	if err := store.RegisterDesktop(&Desktop{
		DesktopID: reg.DesktopID,
		Name:      reg.Name,
		Algorithm: reg.Algorithm,
		PublicKey: pub,
	}); err != nil {
		if errors.Is(err, ErrDeviceAlreadyTrusted) {
			writeError(w, http.StatusConflict, "a different desktop is already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleGetTrustedDesktop(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	d := store.TrustedDesktop()
	if d == nil {
		writeError(w, http.StatusNotFound, "no trusted desktop registered")
		return
	}
	der, err := x509.MarshalPKIXPublicKey(d.PublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, TrustedDesktopResponse{
		DesktopID: d.DesktopID,
		Name:      d.Name,
		Algorithm: d.Algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(der),
	})
}

func handleAttachReleaseRequest(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ReleaseRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed or invalid JSON")
		return
	}
	if req.Protocol != "universal-auth:secure-release:v1" {
		writeError(w, http.StatusBadRequest, "unsupported release protocol")
		return
	}
	if req.DesktopID == "" || req.DesktopAlgorithm == "" || req.DesktopEphemeralPublic == "" || req.CredentialPackage == "" || req.PackageHash == "" || req.DesktopSignature == "" {
		writeError(w, http.StatusBadRequest, "missing required release fields")
		return
	}
	updated, err := store.AttachReleaseRequest(id, req)
	if err != nil {
		if errors.Is(err, ErrRequestNotFound) {
			writeError(w, http.StatusNotFound, "request not found")
		} else if errors.Is(err, ErrInvalidReleaseState) {
			writeError(w, http.StatusConflict, "request is not pending")
		} else if errors.Is(err, ErrReleaseAlreadyAttached) {
			writeError(w, http.StatusConflict, "release request already attached")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func handleAttachReleaseResponse(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var resp ReleaseResponse
	if err := decodeJSON(w, r, &resp); err != nil {
		writeError(w, http.StatusBadRequest, "malformed or invalid JSON")
		return
	}
	if resp.Protocol != "universal-auth:secure-release:v1" || resp.CredentialID == "" || resp.PackageHash == "" || resp.PixelVaultKeyID == "" || resp.PixelEphemeralPublic == "" || resp.TransferNonce == "" || resp.EncryptedDEK == "" {
		writeError(w, http.StatusBadRequest, "missing required release response fields")
		return
	}
	updated, err := store.AttachReleaseResponse(id, resp)
	if err != nil {
		if errors.Is(err, ErrRequestNotFound) {
			writeError(w, http.StatusNotFound, "request not found")
		} else if errors.Is(err, ErrInvalidReleaseState) {
			writeError(w, http.StatusConflict, "request is not pending")
		} else if errors.Is(err, ErrResponseAlreadyAttached) {
			writeError(w, http.StatusConflict, "release response already attached")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func parseP256PublicKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("invalid public key encoding")
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("invalid public key")
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key must be ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("public key must be P-256")
	}
	return pub, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return errors.New("trailing data in request body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func authMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, v1Prefix) {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, authHeaderPrefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		provided := strings.TrimPrefix(auth, authHeaderPrefix)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
