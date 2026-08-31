package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	token := os.Getenv("BROKER_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "BROKER_TOKEN is required")
		os.Exit(1)
	}

	dbPath := os.Getenv("BROKER_DB")
	if dbPath == "" {
		dbPath = "/data/broker.db"
	}

	store, err := NewStore(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open broker store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	handler := newServer(store, token)

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Println("auth-broker listening on :8080")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
