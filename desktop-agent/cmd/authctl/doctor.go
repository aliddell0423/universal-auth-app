package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/doctor"
)

func doctorCmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	origin := fs.String("origin", "", "origin to verify a stored credential")
	jsonOut := fs.Bool("json", false, "output JSON")
	section := fs.String("section", "", "run only the named section (local, broker, vault, browser)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitError)
	}
	if *section != "" && *section != "local" && *section != "broker" && *section != "vault" && *section != "browser" {
		fmt.Fprintf(os.Stderr, "error: unknown section %q; use local, broker, vault, or browser\n", *section)
		os.Exit(exitError)
	}
	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		cfg = &config.Config{}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	report := doctor.Run(ctx, cfg, err, doctor.Flags{
		Origin:  *origin,
		JSON:    *jsonOut,
		Section: *section,
	})

	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(exitError)
		}
	} else {
		doctor.RenderTerminal(os.Stdout, report)
	}

	os.Exit(report.ExitCode)
}
