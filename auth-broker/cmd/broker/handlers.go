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
	"log"
	"net/http"
	"strings"

	"auth-broker/internal/model"
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
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { handleReady(w, r, store) })
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
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.healthz", "method not allowed", "Use GET.", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReady(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.readyz", "method not allowed", "Use GET.", false)
		return
	}
	if err := store.Ready(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, model.NewApiError(
			"UA-BROKER-009",
			"broker.readyz",
			"Broker is not ready.",
			"Check the broker logs and verify the data volume.",
			false,
		))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleCreate(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodPost {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.create_request", "method not allowed", "Use POST.", false)
		return
	}
	var c CreateRequest
	if err := decodeJSON(w, r, &c); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.create_request", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	if c.Source == "" || c.Kind == "" || c.Resource == "" || c.Message == "" || c.ClientNonce == "" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.create_request", "missing required fields", "Provide source, kind, resource, message and client_nonce.", false)
		return
	}
	traceID := r.Header.Get("X-Universal-Auth-Trace-ID")
	req, err := store.Create(c, traceID)
	if err != nil {
		if errors.Is(err, ErrMissingClientNonce) {
			writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.create_request", "client_nonce is required", "Provide a client_nonce.", false)
		} else {
			writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.create_request", "Failed to create request.", "Check the broker logs.", false)
		}
		return
	}
	writeJSON(w, http.StatusCreated, req)
	log.Printf("[trace=%s] [request=%s] created status=pending", req.TraceID, req.ID)
}

func handleListPending(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.list_pending", "method not allowed", "Use GET.", false)
		return
	}
	writeJSON(w, http.StatusOK, store.ListPending())
}

func handleRequestByID(w http.ResponseWriter, r *http.Request, store *Store) {
	suffix := strings.TrimPrefix(r.URL.Path, "/v1/requests/")
	if suffix == "" || strings.HasSuffix(suffix, "/") {
		writeApiError(w, http.StatusNotFound, "UA-BROKER-003", "broker.request", "request not found", "Provide a valid request ID.", false)
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
	writeApiError(w, http.StatusNotFound, "UA-BROKER-003", "broker.request", "request not found", "Provide a valid request ID.", false)
}

func handleGet(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.request_fetch", "method not allowed", "Use GET.", false)
		return
	}
	req, ok := store.Get(id)
	if !ok {
		writeApiError(w, http.StatusNotFound, "UA-BROKER-003", "broker.request_fetch", "request not found", "The request may have expired.", false)
		return
	}
	writeJSON(w, http.StatusOK, req)
	log.Printf("[trace=%s] [request=%s] get status=%s", req.TraceID, req.ID, req.Status)
}

func handleDecision(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	if r.Method != http.MethodPost {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.decision", "method not allowed", "Use POST.", false)
		return
	}
	var d Decision
	if err := decodeJSON(w, r, &d); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.decision", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	if d.Decision != "approved" && d.Decision != "denied" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.decision", "invalid decision value", "Use 'approved' or 'denied'.", false)
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
			writeApiError(w, http.StatusNotFound, "UA-BROKER-003", "broker.decision", "request not found", "The request may have expired.", false)
		case errors.Is(err, ErrInvalidDecision):
			writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.decision", "invalid decision for this request kind", "Check the request kind.", false)
		case errors.Is(err, ErrRequestAlreadyDecided):
			writeApiError(w, http.StatusConflict, "UA-BROKER-006", "broker.decision", "request already decided", "This request has already been processed.", false)
		case errors.Is(err, ErrDeviceNotFound):
			writeApiError(w, http.StatusForbidden, "UA-BROKER-001", "broker.decision", "device not registered", "Run 'authctl pair'.", false)
		case errors.Is(err, ErrDeviceMismatch):
			writeApiError(w, http.StatusForbidden, "UA-BROKER-001", "broker.decision", "device id does not match the trusted device", "Run 'authctl pair'.", false)
		case errors.Is(err, ErrInvalidSignature):
			writeApiError(w, http.StatusForbidden, "UA-CRYPTO-002", "broker.decision", "invalid signature", "Ensure the Pixel signed the correct payload.", false)
		default:
			writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.decision", "Failed to record decision.", "Check the broker logs.", false)
		}
		return
	}
	writeJSON(w, http.StatusOK, req)
	log.Printf("[trace=%s] [request=%s] decision=%s", req.TraceID, req.ID, req.Status)
}

func handleRegisterDevice(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodPost {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.register_device", "method not allowed", "Use POST.", false)
		return
	}
	var reg DeviceRegistration
	if err := decodeJSON(w, r, &reg); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	if reg.Algorithm != "ECDSA_P256_SHA256" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "unsupported algorithm", "Use ECDSA_P256_SHA256.", false)
		return
	}
	if reg.DeviceID == "" || reg.Name == "" || reg.PublicKey == "" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "missing required fields", "Provide device_id, name and public_key.", false)
		return
	}

	pub, err := parseP256PublicKey(reg.PublicKey)
	if err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", err.Error(), "Provide a valid P-256 ECDSA public key.", false)
		return
	}
	if deviceID(pub) != reg.DeviceID {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "device_id does not match public key", "Verify the device fingerprint.", false)
		return
	}
	if reg.VaultKeyID == "" || reg.VaultAlgorithm == "" || reg.VaultPublicKey == "" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "missing vault key fields", "Provide vault_key_id, vault_algorithm and vault_public_key.", false)
		return
	}
	if reg.VaultAlgorithm != "ECDH_P256_HKDF_SHA256" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "unsupported vault algorithm", "Use ECDH_P256_HKDF_SHA256.", false)
		return
	}
	vaultPub, err := parseP256PublicKey(reg.VaultPublicKey)
	if err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "vault public key: "+err.Error(), "Provide a valid P-256 ECDSA public key.", false)
		return
	}
	if deviceID(vaultPub) != reg.VaultKeyID {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_device", "vault_key_id does not match vault public key", "Verify the vault key fingerprint.", false)
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
			writeApiError(w, http.StatusConflict, "UA-BROKER-006", "broker.register_device", "a different device is already registered", "Run 'authctl pair'.", false)
			return
		}
		writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.register_device", "Failed to register device.", "Check the broker logs.", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleGetTrustedDevice(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.trusted_device", "method not allowed", "Use GET.", false)
		return
	}
	dev := store.TrustedDevice()
	if dev == nil {
		writeApiError(w, http.StatusNotFound, "UA-BROKER-001", "broker.trusted_device", "no trusted device registered", "Run 'authctl pair'.", false)
		return
	}
	der, err := x509.MarshalPKIXPublicKey(dev.PublicKey)
	if err != nil {
		writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.trusted_device", "Failed to marshal device key.", "Check the broker logs.", false)
		return
	}
	vaultDER, err := x509.MarshalPKIXPublicKey(dev.VaultPublicKey)
	if err != nil {
		writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.trusted_device", "Failed to marshal vault key.", "Check the broker logs.", false)
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
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.register_desktop", "method not allowed", "Use POST.", false)
		return
	}
	var reg DesktopRegistration
	if err := decodeJSON(w, r, &reg); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_desktop", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	if reg.Algorithm != "ECDSA_P256_SHA256" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_desktop", "unsupported algorithm", "Use ECDSA_P256_SHA256.", false)
		return
	}
	if reg.DesktopID == "" || reg.Name == "" || reg.PublicKey == "" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_desktop", "missing required fields", "Provide desktop_id, name and public_key.", false)
		return
	}
	pub, err := parseP256PublicKey(reg.PublicKey)
	if err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_desktop", err.Error(), "Provide a valid P-256 ECDSA public key.", false)
		return
	}
	if desktopID(pub) != reg.DesktopID {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.register_desktop", "desktop_id does not match public key", "Verify the desktop fingerprint.", false)
		return
	}
	if err := store.RegisterDesktop(&Desktop{
		DesktopID: reg.DesktopID,
		Name:      reg.Name,
		Algorithm: reg.Algorithm,
		PublicKey: pub,
	}); err != nil {
		if errors.Is(err, ErrDeviceAlreadyTrusted) {
			writeApiError(w, http.StatusConflict, "UA-BROKER-006", "broker.register_desktop", "a different desktop is already trusted", "Run 'authctl desktop-register' or clear existing trust.", false)
			return
		}
		writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.register_desktop", "Failed to register desktop.", "Check the broker logs.", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleGetTrustedDesktop(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.trusted_desktop", "method not allowed", "Use GET.", false)
		return
	}
	d := store.TrustedDesktop()
	if d == nil {
		writeApiError(w, http.StatusNotFound, "UA-BROKER-002", "broker.trusted_desktop", "no trusted desktop registered", "Run 'authctl desktop-register'.", false)
		return
	}
	der, err := x509.MarshalPKIXPublicKey(d.PublicKey)
	if err != nil {
		writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.trusted_desktop", "Failed to marshal desktop key.", "Check the broker logs.", false)
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
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.attach_release", "method not allowed", "Use POST.", false)
		return
	}
	var req ReleaseRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.attach_release", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	if req.Protocol != "universal-auth:secure-release:v1" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.attach_release", "unsupported release protocol", "Use universal-auth:secure-release:v1.", false)
		return
	}
	if req.DesktopID == "" || req.DesktopAlgorithm == "" || req.DesktopEphemeralPublic == "" || req.CredentialPackage == "" || req.PackageHash == "" || req.DesktopSignature == "" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.attach_release", "missing required release fields", "Check the secure release payload.", false)
		return
	}
	updated, err := store.AttachReleaseRequest(id, req)
	if err != nil {
		if errors.Is(err, ErrRequestNotFound) {
			writeApiError(w, http.StatusNotFound, "UA-BROKER-003", "broker.attach_release", "request not found", "The request may have expired.", false)
		} else if errors.Is(err, ErrInvalidReleaseState) {
			writeApiError(w, http.StatusConflict, "UA-BROKER-006", "broker.attach_release", "request is not pending", "Create a new request.", false)
		} else if errors.Is(err, ErrReleaseAlreadyAttached) {
			writeApiError(w, http.StatusConflict, "UA-BROKER-006", "broker.attach_release", "release request already attached", "This request already has a release payload.", false)
		} else {
			writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.attach_release", "Failed to attach release request.", "Check the broker logs.", false)
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
	log.Printf("[trace=%s] [request=%s] attached release_request", updated.TraceID, updated.ID)
}

func handleAttachReleaseResponse(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	if r.Method != http.MethodPost {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-BROKER-007", "broker.attach_release_response", "method not allowed", "Use POST.", false)
		return
	}
	var resp ReleaseResponse
	if err := decodeJSON(w, r, &resp); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.attach_release_response", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	if resp.Protocol != "universal-auth:secure-release:v1" || resp.CredentialID == "" || resp.PackageHash == "" || resp.PixelVaultKeyID == "" || resp.PixelEphemeralPublic == "" || resp.TransferNonce == "" || resp.EncryptedDEK == "" {
		writeApiError(w, http.StatusBadRequest, "UA-BROKER-003", "broker.attach_release_response", "missing required release response fields", "Check the secure release response.", false)
		return
	}
	updated, err := store.AttachReleaseResponse(id, resp)
	if err != nil {
		if errors.Is(err, ErrRequestNotFound) {
			writeApiError(w, http.StatusNotFound, "UA-BROKER-003", "broker.attach_release_response", "request not found", "The request may have expired.", false)
		} else if errors.Is(err, ErrInvalidReleaseState) {
			writeApiError(w, http.StatusConflict, "UA-BROKER-006", "broker.attach_release_response", "request is not pending", "Create a new request.", false)
		} else if errors.Is(err, ErrResponseAlreadyAttached) {
			writeApiError(w, http.StatusConflict, "UA-BROKER-006", "broker.attach_release_response", "release response already attached", "This request already has a response.", false)
		} else {
			writeApiError(w, http.StatusInternalServerError, "UA-BROKER-005", "broker.attach_release_response", "Failed to attach release response.", "Check the broker logs.", false)
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
	log.Printf("[trace=%s] [request=%s] attached release_response status=%s", updated.TraceID, updated.ID, updated.Status)
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

func writeApiError(w http.ResponseWriter, status int, code, stage, message, action string, retryable bool) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(model.NewApiError(code, stage, message, action, retryable))
}

func authMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, v1Prefix) {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, authHeaderPrefix) {
			writeApiError(w, http.StatusUnauthorized, "UA-BROKER-008", "broker.auth", "unauthorized", "Provide a valid bearer token.", false)
			return
		}
		provided := strings.TrimPrefix(auth, authHeaderPrefix)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeApiError(w, http.StatusUnauthorized, "UA-BROKER-008", "broker.auth", "unauthorized", "Provide a valid bearer token.", false)
			return
		}
		next.ServeHTTP(w, r)
	})
}
