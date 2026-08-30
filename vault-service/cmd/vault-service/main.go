package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"vault-service/internal/api"
	"vault-service/internal/config"
	"vault-service/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	srv := api.NewServer(db, cfg.Token)
	fmt.Printf("vault-service listening on %s\n", cfg.Addr)

	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
