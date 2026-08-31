package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
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
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
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
			"Vault storage is not ready: "+err.Error(),
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
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	meta, err := s.store.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in model.CredentialPackageInput
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "malformed or invalid JSON")
		return
	}
	pkg, err := s.store.CreateCredential(r.Context(), in)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "already exists") {
			writeError(w, http.StatusConflict, "credential already exists for origin")
		} else if strings.Contains(msg, "required") || strings.Contains(msg, "unsupported") || strings.Contains(msg, "must") || strings.Contains(msg, "wrap_ephemeral") {
			writeError(w, http.StatusBadRequest, msg)
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, pkg)
}

func (s *Server) handleExists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		writeError(w, http.StatusBadRequest, "origin query parameter is required")
		return
	}
	exists, err := s.store.Exists(r.Context(), origin)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"exists": exists})
}

func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		writeError(w, http.StatusBadRequest, "origin query parameter is required")
		return
	}
	pkg, err := s.store.GetPackageByOrigin(r.Context(), origin)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pkg)
}

func (s *Server) handleCredentialByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/credentials/")
	if id == "" || strings.HasSuffix(id, "/") {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "credential not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
