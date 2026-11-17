package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"auth-broker/internal/push"
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

	var pusher push.Sender = push.NopSender{}
	if path := os.Getenv("FCM_SERVICE_ACCOUNT_FILE"); path != "" {
		sender, err := push.NewFCMSenderFromFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load FCM service account: %v\n", err)
			os.Exit(1)
		}
		pusher = sender
		fmt.Println("push delivery: FCM enabled")
	} else {
		fmt.Println("push delivery: disabled (set FCM_SERVICE_ACCOUNT_FILE to enable)")
	}

	handler := newServerWithPush(store, token, pusher)

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
