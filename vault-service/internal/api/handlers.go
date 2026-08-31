package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"vault-service/internal/model"
	"vault-service/internal/store"
)

const (
	maxBodySize      = 64 * 1024
	authHeaderPrefix = "Bearer "
	v1Prefix         = "/v1/"
)

type Server struct {
	store *store.DB
	token string
}

func NewServer(db *store.DB, token string) *Server {
	return &Server{store: db, token: token}
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
	meta, err := s.store.List(r.Context())
	if err != nil {
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
			writeApiError(w, http.StatusConflict, "UA-VAULT-002", "vault.create", "credential already exists for origin", "Delete the existing credential first.", false)
		} else if strings.Contains(msg, "required") || strings.Contains(msg, "unsupported") || strings.Contains(msg, "must") || strings.Contains(msg, "wrap_ephemeral") {
			writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.create", msg, "Check the credential package.", false)
		} else {
			writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.create", "Failed to store credential.", "Check the vault service logs.", false)
		}
		return
	}
	writeJSON(w, http.StatusCreated, pkg)
	log.Printf("[trace=%s] package stored id=%s origin=%s", traceID(r), pkg.CredentialID, pkg.Origin)
}

func (s *Server) handleExists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.exists", "method not allowed", "Use GET.", false)
		return
	}
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.exists", "origin query parameter is required", "Provide an origin.", false)
		return
	}
	exists, err := s.store.Exists(r.Context(), origin)
	if err != nil {
		writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.exists", "Failed to check credential existence.", "Check the vault service logs.", false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"exists": exists})
	log.Printf("[trace=%s] exists checked origin=%s exists=%v", traceID(r), origin, exists)
}

func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.package_fetch", "method not allowed", "Use GET.", false)
		return
	}
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		writeApiError(w, http.StatusBadRequest, "UA-VAULT-003", "vault.package_fetch", "origin query parameter is required", "Provide an origin.", false)
		return
	}
	pkg, err := s.store.GetPackageByOrigin(r.Context(), origin)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeApiError(w, http.StatusNotFound, "UA-VAULT-002", "vault.package_fetch", "credential not found", "Store a credential for this origin.", false)
			return
		}
		writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.package_fetch", "Failed to retrieve credential.", "Check the vault service logs.", false)
		return
	}
	writeJSON(w, http.StatusOK, pkg)
	log.Printf("[trace=%s] package fetched origin=%s", traceID(r), pkg.Origin)
}

func (s *Server) handleCredentialByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/credentials/")
	if id == "" || strings.HasSuffix(id, "/") {
		writeApiError(w, http.StatusNotFound, "UA-VAULT-002", "vault.delete", "credential not found", "Provide a valid credential ID.", false)
		return
	}
	if r.Method != http.MethodDelete {
		writeApiError(w, http.StatusMethodNotAllowed, "UA-VAULT-007", "vault.delete", "method not allowed", "Use DELETE.", false)
		return
	}
	if err := s.store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeApiError(w, http.StatusNotFound, "UA-VAULT-002", "vault.delete", "credential not found", "Provide a valid credential ID.", false)
			return
		}
		writeApiError(w, http.StatusInternalServerError, "UA-VAULT-004", "vault.delete", "Failed to delete credential.", "Check the vault service logs.", false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	log.Printf("[trace=%s] package deleted id=%s", traceID(r), id)
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
