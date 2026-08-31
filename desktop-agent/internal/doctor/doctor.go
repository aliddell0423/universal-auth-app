package doctor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/apierror"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
)

type Status string

const (
	Pass    Status = "PASS"
	Warn    Status = "WARN"
	Skip    Status = "SKIP"
	Fail    Status = "FAIL"
	Unknown Status = "UNKNOWN"
)

type Result struct {
	Section string `json:"section"`
	Check   string `json:"check"`
	Status  Status `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Action  string `json:"action"`
}

type Report struct {
	Results  []Result `json:"results"`
	HasFails bool     `json:"has_fails"`
	ExitCode int      `json:"exit_code"`
	Origin   string   `json:"origin,omitempty"`
}

type Flags struct {
	Origin  string
	JSON    bool
	Section string
}

func Run(ctx context.Context, cfg *config.Config, flags Flags) *Report {
	var results []Result

	if flags.Section == "" || flags.Section == "local" {
		results = append(results, checkLocal(cfg)...)
	}

	brokerClient, vaultClient := newClients(cfg)

	if flags.Section == "" || flags.Section == "broker" {
		results = append(results, checkBroker(ctx, cfg, brokerClient)...)
	}

	if flags.Section == "" || flags.Section == "vault" {
		results = append(results, checkVault(ctx, cfg, vaultClient)...)
	}

	if flags.Section == "" || flags.Section == "browser" {
		results = append(results, checkBrowser()...)
	}

	if flags.Origin != "" {
		results = append(results, checkOrigin(ctx, cfg, vaultClient, flags.Origin)...)
	}

	if flags.Section == "" && flags.Origin == "" {
		results = append(results, Result{
			Section: "Origin",
			Check:   "origin supplied",
			Status:  Warn,
			Code:    "UA-DOCTOR-100",
			Message: "No origin supplied; credential package not tested.",
			Action:  "Run 'authctl doctor --origin https://example.com' to verify a credential.",
		})
	}

	hasFails := false
	for _, r := range results {
		if r.Status == Fail {
			hasFails = true
			break
		}
	}
	exitCode := 0
	if hasFails {
		exitCode = 5
	}
	return &Report{Results: results, HasFails: hasFails, ExitCode: exitCode, Origin: flags.Origin}
}

func newClients(cfg *config.Config) (*broker.Client, *vault.Client) {
	var bc *broker.Client
	var vc *vault.Client

	if b, err := config.LoadBrokerToken(); err == nil && cfg.BrokerURL != "" {
		bc = broker.NewClient(cfg.BrokerURL, b)
	}
	if v, err := config.LoadVaultToken(); err == nil && cfg.VaultURL != "" {
		vc = vault.NewClient(cfg.VaultURL, v)
	}
	return bc, vc
}

func ctxWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func newResult(section, check string, status Status, code, message, action string) Result {
	return Result{
		Section: section,
		Check:   check,
		Status:  status,
		Code:    code,
		Message: message,
		Action:  action,
	}
}

func keyFingerprint(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func parseP256(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("not a P-256 ECDSA key")
	}
	return pub, nil
}

func filePermFix(path string) string {
	return fmt.Sprintf("chmod 600 %s", path)
}

func isNotExist(err error) bool {
	return os.IsNotExist(err)
}

func extractAPIError(err error) *apierror.Error {
	var e *apierror.Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}
