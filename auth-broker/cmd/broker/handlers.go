package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

const (
	maxBodySize      = 64 * 1024
	authHeaderPrefix = "Bearer "
	v1Prefix         = "/v1/"
)

func newServer(store *Store, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/v1/requests/pending", func(w http.ResponseWriter, r *http.Request) { handleListPending(w, r, store) })
	mux.HandleFunc("/v1/requests/", func(w http.ResponseWriter, r *http.Request) { handleRequestByID(w, r, store) })
	mux.HandleFunc("/v1/requests", func(w http.ResponseWriter, r *http.Request) { handleCreate(w, r, store) })
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
	if c.Source == "" || c.Kind == "" || c.Resource == "" || c.Message == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}
	req, err := store.Create(c.Source, c.Kind, c.Resource, c.Message)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
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
	if len(parts) == 2 && parts[1] == "decision" {
		handleDecision(w, r, store, parts[0])
		return
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
	req, err := store.Decide(id, d.Decision)
	if err != nil {
		switch {
		case errors.Is(err, ErrRequestNotFound):
			writeError(w, http.StatusNotFound, "request not found")
		case errors.Is(err, ErrInvalidDecision):
			writeError(w, http.StatusBadRequest, "invalid decision")
		case errors.Is(err, ErrRequestAlreadyDecided):
			writeError(w, http.StatusConflict, "request already decided")
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
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
