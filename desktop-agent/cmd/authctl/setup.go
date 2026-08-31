package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/setup"
)

func setupCmd(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	brokerURL := fs.String("broker", "", "broker base URL")
	vaultURL := fs.String("vault", "", "vault base URL")
	desktopName := fs.String("desktop-name", "Fedora Desktop", "desktop display name")
	checkOnly := fs.Bool("check", false, "report without making changes")
	jsonOut := fs.Bool("json", false, "output JSON")
	skipNativeHost := fs.Bool("skip-native-host", false, "skip building and installing the Firefox native host")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	report := setup.Run(ctx, setup.Options{
		BrokerURL:      *brokerURL,
		VaultURL:       *vaultURL,
		DesktopName:    *desktopName,
		CheckOnly:      *checkOnly,
		SkipNativeHost: *skipNativeHost,
	})

	if *jsonOut {
		if err := setup.RenderJSON(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(exitError)
		}
	} else {
		setup.RenderTerminal(os.Stdout, report)
	}

	os.Exit(report.ExitCode)
}
