package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"vault-service/internal/approval"
	"vault-service/internal/model"
	"vault-service/internal/store"
)

const (
	maxBodySize      = 64 * 1024
	authHeaderPrefix = "Bearer "
	v1Prefix         = "/v1/"
)

type Server struct {
	store    *store.DB
	token    string
	approver *approval.Verifier
}

// NewServer builds the API. approver may be nil, in which case overwrites and
// deletes are refused.
func NewServer(db *store.DB, token string, approver *approval.Verifier) *Server {
	return &Server{store: db, token: token, approver: approver}
}

// replaceBody is the PUT /v1/credentials/{id} body. Approval is the broker's
// request record, decoded leniently because the broker may add fields; only
// the signed fields matter.
type replaceBody struct {
	Package  model.CredentialPackageInput `json:"package"`
	Approval json.RawMessage              `json:"approval"`
}

// deleteBody is the DELETE /v1/credentials/{id} body.
type deleteBody struct {
	Approval json.RawMessage `json:"approval"`
}

func parseApproval(raw json.RawMessage) (*approval.Request, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var req approval.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/v1/credentials", s.handleCredentials)
	mux.HandleFunc("/v1/credentials/exists", s.handleExists)
	mux.HandleFunc("/v1/credentials/package", s.handlePackage)
	mux.HandleFunc("/v1/credentials/", s.handleCredentialByID)
	return authMiddleware(mux, s.token)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.healthz", "method not allowed", "Use GET.", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.readyz", "method not allowed", "Use GET.", false)
		return
	}
	if err := s.store.Ready(); err != nil {
		if errors.Is(err, store.ErrIncompatibleSchema) {
			writeJSON(w, http.StatusServiceUnavailable, model.NewApiError(
				"UA-VAULT-001",
				"vault.readyz",
				"Vault storage schema is incompatible with this version. The existing database must be migrated or recreated.",
				"Run 'authctl doctor' for repair instructions.",
				false,
			))
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, model.NewApiError(
			"UA-VAULT-004",
			"vault.readyz",
			"Vault storage is not ready.",
			"Check the vault service logs and run 'authctl doctor'.",
			false,
		))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleList(w, r)
	case http.MethodPost:
		s.handleCreate(w, r)
	default:
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.credentials", "method not allowed", "Use GET or POST.", false)
	}
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	resource, kind := resourceParams(r)
	meta, err := s.store.ListFiltered(r.Context(), resource, kind)
	if err != nil {
		if strings.Contains(err.Error(), "invalid resource") {
			writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.list", err.Error(), "Check the resource parameter.", false)
			return
		}
		writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.list", "Failed to list credentials.", "Check the vault service logs.", false)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in model.CredentialPackageInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.create", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	pkg, err := s.store.CreateCredential(r.Context(), in)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "already exists") {
			writeApiError(w, http.StatusConflict, "UA-VAULT-002", "vault.create", "credential already exists for this resource", "Delete the existing credential first.", false)
		} else if strings.Contains(msg, "required") || strings.Contains(msg, "unsupported") || strings.Contains(msg, "must") || strings.Contains(msg, "wrap_ephemeral") {
			writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.create", msg, "Check the credential package.", false)
		} else {
			writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.create", "Failed to store credential.", "Check the vault service logs.", false)
		}
		return
	}
	writeJSON(w, http.StatusCreated, pkg)
	log.Printf("[trace=%s] package stored id=%s resource=%s kind=%s", traceID(r), pkg.CredentialID, pkg.Resource+pkg.Origin, pkg.Kind)
}

func (s *Server) handleExists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.exists", "method not allowed", "Use GET.", false)
		return
	}
	resource, kind := resourceParams(r)
	if resource == "" {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.exists", "resource query parameter is required", "Provide a resource.", false)
		return
	}
	exists, err := s.store.Exists(r.Context(), resource, kind)
	if err != nil {
		writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.exists", "Failed to check credential existence.", "Check the vault service logs.", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"exists": exists})
	log.Printf("[trace=%s] exists checked resource=%s kind=%s exists=%v", traceID(r), resource, kind, exists)
}

func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.package_fetch", "method not allowed", "Use GET.", false)
		return
	}
	resource, kind := resourceParams(r)
	if resource == "" {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.package_fetch", "resource query parameter is required", "Provide a resource.", false)
		return
	}
	var account *string
	if r.URL.Query().Has("account") {
		a := r.URL.Query().Get("account")
		account = &a
	}
	pkg, err := s.store.GetPackage(r.Context(), resource, kind, account)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeApiError(w, http.StatusNotFound, "UA-VAULT-002", "vault.package_fetch", "credential not found", "Store a credential for this resource.", false)
			return
		}
		if errors.Is(err, store.ErrAmbiguous) {
			writeApiError(w, http.StatusConflict, "UA-VAULT-009", "vault.package_fetch", "multiple credentials match resource", "Specify kind or account, or fetch by credential ID.", false)
			return
		}
		writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.package_fetch", "Failed to retrieve credential.", "Check the vault service logs.", false)
		return
	}
	writeJSON(w, http.StatusOK, pkg)
	log.Printf("[trace=%s] package fetched resource=%s kind=%s", traceID(r), pkg.Resource+pkg.Origin, pkg.Kind)
}

func (s *Server) handleCredentialByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/credentials/")
	if id == "" || strings.Contains(id, "/") {
		writeApiError(w, http.StatusNotFound, "UA-VAULT-002", "vault.credential", "credential not found", "Provide a valid credential ID.", false)
		return
	}
	switch r.Method {
	case http.MethodGet:
		pkg, err := s.store.GetPackageByID(r.Context(), id)
		if err != nil {
			s.writeStoreError(w, err, "vault.package_fetch")
			return
		}
		writeJSON(w, http.StatusOK, pkg)
	case http.MethodPut:
		s.handleReplace(w, r, id)
	case http.MethodDelete:
		s.handleDelete(w, r, id)
	default:
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.credential", "method not allowed", "Use GET, PUT or DELETE.", false)
	}
}

func (s *Server) handleReplace(w http.ResponseWriter, r *http.Request, id string) {
	var body replaceBody
	if err := decodeJSON(w, r, &body); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.update", "malformed or invalid JSON", "Check the request body.", false)
		return
	}
	current, err := s.store.GetPackageByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "vault.update")
		return
	}
	appr, err := parseApproval(body.Approval)
	if err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.update", "malformed approval", "Check the request body.", false)
		return
	}
	op := approval.Op{Op: approval.OpUpdate, CredentialID: id, Package: &body.Package}
	if err := s.approver.Verify(appr, op, resourceOf(current)); err != nil {
		writeApprovalError(w, err, "vault.update")
		return
	}
	pkg, err := s.store.Replace(r.Context(), id, body.Package, appr.ID)
	if err != nil {
		s.writeStoreError(w, err, "vault.update")
		return
	}
	writeJSON(w, http.StatusOK, pkg)
	log.Printf("[trace=%s] package replaced id=%s resource=%s approval=%s", traceID(r), id, resourceOf(pkg), appr.ID)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	var body deleteBody
	if err := decodeJSON(w, r, &body); err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.delete", "malformed or invalid JSON", "Send {\"approval\": ...}.", false)
		return
	}
	current, err := s.store.GetPackageByID(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err, "vault.delete")
		return
	}
	appr, err := parseApproval(body.Approval)
	if err != nil {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.delete", "malformed approval", "Check the request body.", false)
		return
	}
	op := approval.Op{Op: approval.OpDelete, CredentialID: id}
	if err := s.approver.Verify(appr, op, resourceOf(current)); err != nil {
		writeApprovalError(w, err, "vault.delete")
		return
	}
	if err := s.store.Delete(r.Context(), id, appr.ID); err != nil {
		s.writeStoreError(w, err, "vault.delete")
		return
	}
	w.WriteHeader(http.StatusNoContent)
	log.Printf("[trace=%s] package deleted id=%s approval=%s", traceID(r), id, appr.ID)
}

func resourceOf(p model.CredentialPackage) string {
	if p.Resource != "" {
		return p.Resource
	}
	return p.Origin
}

func (s *Server) writeStoreError(w http.ResponseWriter, err error, stage string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeApiError(w, http.StatusNotFound, "UA-VAULT-002", stage, "credential not found", "Provide a valid credential ID.", false)
	case errors.Is(err, store.ErrApprovalReused):
		writeApiError(w, http.StatusConflict, "UA-VAULT-010", stage, err.Error(), "Request a new approval.", false)
	case strings.Contains(err.Error(), "already exists"):
		writeApiError(w, http.StatusConflict, "UA-VAULT-002", stage, "credential already exists for this resource and account", "Use a different account label.", false)
	case strings.Contains(err.Error(), "required"), strings.Contains(err.Error(), "must"),
		strings.Contains(err.Error(), "unsupported"), strings.Contains(err.Error(), "cannot change"),
		strings.Contains(err.Error(), "invalid"):
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", stage, err.Error(), "Check the credential package.", false)
	default:
		log.Printf("%s: %v", stage, err)
		writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", stage, "Vault storage error.", "Check the vault service logs.", false)
	}
}

func writeApprovalError(w http.ResponseWriter, err error, stage string) {
	status := http.StatusForbidden
	if errors.Is(err, approval.ErrNotConfigured) {
		status = http.StatusServiceUnavailable
	}
	writeApiError(w, status, "UA-VAULT-011", stage, err.Error(), "Approve the change on the Pixel and retry.", false)
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

// resourceParams extracts the resource and optional kind query parameters.
// The legacy "origin" parameter is accepted as an alias for resource.
func resourceParams(r *http.Request) (resource, kind string) {
	resource = r.URL.Query().Get("resource")
	if resource == "" {
		resource = r.URL.Query().Get("origin")
	}
	kind = r.URL.Query().Get("kind")
	return resource, kind
}

func traceID(r *http.Request) string {
	return r.Header.Get("X-Universal-Auth-Trace-ID")
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
			writeApiError(w, http.StatusUnauthorized, "UA-VAULT-008", "vault.auth", "unauthorized", "Provide a valid bearer token.", false)
			return
		}
		provided := strings.TrimPrefix(auth, authHeaderPrefix)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			writeApiError(w, http.StatusUnauthorized, "UA-VAULT-008", "vault.auth", "unauthorized", "Provide a valid bearer token.", false)
			return
		}
		next.ServeHTTP(w, r)
	})
}
