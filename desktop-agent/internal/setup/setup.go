package setup

import (
	"context"
	"fmt"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
)

// Status describes the outcome of a single setup step.
type Status string

const (
	Pass   Status = "PASS"
	Create Status = "CREATE"
	Update Status = "UPDATE"
	Action Status = "ACTION"
	Skip   Status = "SKIP"
	Fail   Status = "FAIL"
)

// Step is one line of setup output.
type Step struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Report is the full result of a setup run.
type Report struct {
	Steps      []Step `json:"steps"`
	HasFails   bool   `json:"has_fails"`
	HasActions bool   `json:"has_actions"`
	ExitCode   int    `json:"exit_code"`
}

// Options controls a setup run.
type Options struct {
	BrokerURL   string
	VaultURL    string
	DesktopName string
	// CheckOnly makes the run read-only; no files are written and no
	// registration requests are sent.
	CheckOnly bool
	// ConfigPath overrides the configuration path, primarily for tests.
	ConfigPath string
	// IdentityPath overrides the desktop identity path, primarily for tests.
	IdentityPath string
	// SkipNativeHost skips building/installing the Firefox native host.
	SkipNativeHost bool
}

const requestTimeout = 5 * time.Second

// Run executes the setup steps in dependency order and returns a report.
func Run(ctx context.Context, opts Options) *Report {
	r := &Report{}

	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}

	cfg, cfgErr := config.Load(cfgPath)
	if cfgErr != nil {
		cfg = &config.Config{}
	}

	// Resolve the effective broker/vault URLs: flags win, then existing config.
	brokerURL := firstNonEmpty(opts.BrokerURL, cfg.BrokerURL)
	vaultURL := firstNonEmpty(opts.VaultURL, cfg.VaultURL)

	if brokerURL == "" {
		r.add(Step{Name: "broker URL", Status: Fail, Code: "UA-SETUP-001",
			Message: "No broker URL configured.",
			Detail:  "Pass --broker http://host:8080 on the first run."})
		return r.finish()
	}
	if vaultURL == "" {
		r.add(Step{Name: "vault URL", Status: Fail, Code: "UA-SETUP-002",
			Message: "No vault URL configured.",
			Detail:  "Pass --vault http://host:8081 on the first run."})
		return r.finish()
	}

	brokerToken, brokerTokenErr := config.LoadBrokerToken()
	vaultToken, vaultTokenErr := config.LoadVaultToken()

	if brokerTokenErr != nil {
		r.add(Step{Name: "broker token", Status: Fail, Code: "UA-CONFIG-007",
			Message: "Broker token is unavailable.",
			Detail:  brokerTokenErr.Error()})
	} else {
		r.add(Step{Name: "broker token", Status: Pass, Message: "Broker token is available."})
	}
	if vaultTokenErr != nil {
		r.add(Step{Name: "vault token", Status: Fail, Code: "UA-CONFIG-005",
			Message: "Vault token is unavailable.",
			Detail:  vaultTokenErr.Error()})
	} else {
		r.add(Step{Name: "vault token", Status: Pass, Message: "Vault token is available."})
	}
	if brokerTokenErr != nil || vaultTokenErr != nil {
		return r.finish()
	}

	brokerClient := broker.NewClient(brokerURL, brokerToken)
	vaultClient := vault.NewClient(vaultURL, vaultToken)

	reachCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	if err := brokerClient.Ready(reachCtx); err != nil {
		r.add(Step{Name: "broker reachable", Status: Fail, Code: "UA-BROKER-009",
			Message: "Broker is not ready.",
			Detail:  err.Error()})
		return r.finish()
	}
	r.add(Step{Name: "broker reachable", Status: Pass, Message: fmt.Sprintf("Broker %s is ready.", brokerURL)})

	if err := vaultClient.Ready(reachCtx); err != nil {
		r.add(Step{Name: "vault reachable", Status: Fail, Code: "UA-VAULT-004",
			Message: "Vault is not ready.",
			Detail:  err.Error()})
		return r.finish()
	}
	r.add(Step{Name: "vault reachable", Status: Pass, Message: fmt.Sprintf("Vault %s is ready.", vaultURL)})

	// Persist the resolved endpoints without destroying other config fields.
	configChanged := cfg.BrokerURL != brokerURL || cfg.VaultURL != vaultURL ||
		cfg.ConfigVersion != config.CurrentConfigVersion
	cfg.BrokerURL = brokerURL
	cfg.VaultURL = vaultURL

	switch {
	case opts.CheckOnly && configChanged:
		r.add(Step{Name: "local configuration", Status: Action,
			Message: "Configuration would be updated.",
			Detail:  "Run 'authctl setup' without --check to apply."})
	case opts.CheckOnly:
		r.add(Step{Name: "local configuration", Status: Pass, Message: "Configuration is current."})
	case configChanged:
		if err := cfg.Save(cfgPath); err != nil {
			r.add(Step{Name: "local configuration", Status: Fail, Code: "UA-SETUP-003",
				Message: "Could not write configuration.", Detail: err.Error()})
			return r.finish()
		}
		r.add(Step{Name: "local configuration", Status: Update, Message: fmt.Sprintf("Updated %s.", cfgPath)})
	default:
		r.add(Step{Name: "local configuration", Status: Pass, Message: "Configuration is current."})
	}

	r.runIdentityAndRegistration(ctx, opts, cfg, cfgPath, brokerClient)
	r.runNativeHost(opts)
	r.runPixelPairing(ctx, opts, cfg, cfgPath, brokerClient)

	return r.finish()
}

func (r *Report) add(s Step) {
	r.Steps = append(r.Steps, s)
}

func (r *Report) finish() *Report {
	for _, s := range r.Steps {
		if s.Status == Fail {
			r.HasFails = true
		}
		if s.Status == Action {
			r.HasActions = true
		}
	}
	if r.HasFails {
		r.ExitCode = 5
	}
	return r
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
