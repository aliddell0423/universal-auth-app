package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/apierror"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/logins"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/nm"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultwrite"
)

const (
	hostVersion     = "0.3.0"
	protocolVersion = 3
	approvalTimeout = 90 * time.Second
)

// inMessage is a request from the extension. Origin is always derived by the
// extension's background script from the sending tab, never from page data.
type inMessage struct {
	Type         string `json:"type"`
	Origin       string `json:"origin"`
	CredentialID string `json:"credential_id,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	Account      string `json:"account,omitempty"`
	// SaveAs picks where to store a login: the origin or one of its parent
	// domains (see logins.SaveTargets).
	SaveAs string `json:"save_as,omitempty"`
	// Resource is the stored origin to link to Origin (link_site/unlink_site).
	Resource string `json:"resource,omitempty"`
}

type loginMeta struct {
	CredentialID string `json:"credential_id"`
	Resource     string `json:"resource"`
	Account      string `json:"account"`
	Match        string `json:"match,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type outMessage struct {
	Status          string      `json:"status"`
	Username        string      `json:"username,omitempty"`
	Password        string      `json:"password,omitempty"`
	CredentialID    string      `json:"credential_id,omitempty"`
	Account         string      `json:"account,omitempty"`
	Logins          []loginMeta `json:"logins,omitempty"`
	SaveTargets     []string    `json:"save_targets,omitempty"`
	Code            string      `json:"code,omitempty"`
	Stage           string      `json:"stage,omitempty"`
	Error           string      `json:"error,omitempty"`
	TraceID         string      `json:"trace_id,omitempty"`
	RequestID       string      `json:"request_id,omitempty"`
	Retryable       bool        `json:"retryable"`
	Action          string      `json:"action,omitempty"`
	HostVersion     string      `json:"host_version,omitempty"`
	ProtocolVersion int         `json:"protocol_version,omitempty"`
	ConfigLoaded    bool        `json:"config_loaded,omitempty"`
	VaultConfigured bool        `json:"vault_configured,omitempty"`
	PixelPaired     bool        `json:"pixel_paired,omitempty"`
}

func main() {
	var req inMessage
	if err := nm.ReadMessage(os.Stdin, &req); err != nil {
		fmt.Fprintf(os.Stderr, "read native message: %v\n", err)
		_ = nm.WriteMessage(os.Stdout, fail(generateTraceID(), "UA-BROWSER-003", "browser.native_read", "Failed to read native message.", "Check the native host logs."))
		os.Exit(1)
	}
	if err := nm.WriteMessage(os.Stdout, handle(req)); err != nil {
		fmt.Fprintf(os.Stderr, "write native message: %v\n", err)
		os.Exit(1)
	}
}

func handle(req inMessage) outMessage {
	traceID := generateTraceID()
	if req.Type == "diagnose" {
		return diagnose(traceID)
	}
	handlers := map[string]func(*logins.Service, string, inMessage, string) outMessage{
		"list_logins":    listLogins,
		"get_credential": getCredential,
		"save_login":     saveLogin,
		"update_login":   updateLogin,
		"delete_login":   deleteLogin,
		"link_site":      linkSite,
		"unlink_site":    linkSite,
		"all_logins":     allLogins,
	}
	h, ok := handlers[req.Type]
	if !ok {
		return fail(traceID, "UA-BROWSER-002", "browser.validate", "Unknown native message type.", "Update the extension and native host together.")
	}
	origin := ""
	if req.Type != "all_logins" {
		var err error
		if origin, err = vaultcrypto.NormalizeOrigin(req.Origin); err != nil {
			return fail(traceID, "UA-BROWSER-002", "browser.validate", "Invalid or missing origin.", "Reload the page and try again.")
		}
	}
	svc, err := logins.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", traceID, err)
		return fail(traceID, "UA-CONFIG-001", "config.load", "Universal Auth is not configured on this computer.", "Run 'authctl doctor'.")
	}
	svc.Timeout = approvalTimeout
	return h(svc, origin, req, traceID)
}

func listLogins(svc *logins.Service, origin string, _ inMessage, traceID string) outMessage {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	matches, err := svc.Matches(ctx, origin, traceID)
	if err != nil {
		return fromError(traceID, err)
	}
	targets, _ := logins.SaveTargets(origin)
	return outMessage{Status: "ok", Logins: toMeta(matches), SaveTargets: targets, TraceID: traceID}
}

func getCredential(svc *logins.Service, origin string, req inMessage, traceID string) outMessage {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	matches, err := svc.Matches(ctx, origin, traceID)
	cancel()
	if err != nil {
		return fromError(traceID, err)
	}
	id := req.CredentialID
	switch {
	case id != "":
		if !slices.ContainsFunc(matches, func(m logins.Match) bool { return m.CredentialID == id }) {
			return outcome("error", traceID, "UA-BROWSER-005", "browser.offered", logins.ErrNotOffered.Error(), "Pick a login listed for this site.")
		}
	case len(matches) == 0:
		return outcome("not_found", traceID, "UA-VAULT-002", "vault.lookup", "No saved login for this site.", "Save one from the Universal Auth menu.")
	case len(matches) > 1:
		return outMessage{Status: "choose", Logins: toMeta(matches), TraceID: traceID}
	default:
		id = matches[0].CredentialID
	}
	res, pkg, err := svc.Release(context.Background(), id, traceID)
	if err != nil {
		return approvalError(traceID, err)
	}
	return outMessage{
		Status: "approved", Username: res.Fields["username"], Password: res.Fields["password"],
		CredentialID: id, Account: pkg.Account, TraceID: res.TraceID, RequestID: res.RequestID,
	}
}

func saveLogin(svc *logins.Service, origin string, req inMessage, traceID string) outMessage {
	if req.Password == "" {
		return fail(traceID, "UA-BROWSER-002", "browser.validate", "Password is empty.", "Fill in the password first.")
	}
	resource, err := saveTarget(origin, req.SaveAs)
	if err != nil {
		return fail(traceID, "UA-BROWSER-002", "browser.validate", err.Error(), "Pick one of the offered sites.")
	}
	account := strings.TrimSpace(req.Account)
	if account == "" {
		account = strings.TrimSpace(req.Username)
	}
	fields := map[string]string{"username": req.Username, "password": req.Password}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pkg, err := svc.Save(ctx, vaultcrypto.KindLogin, resource, account, fields, traceID)
	var exists *logins.ErrExists
	if errors.As(err, &exists) {
		return outMessage{Status: "exists", CredentialID: exists.CredentialID, Account: account, TraceID: traceID}
	}
	if err != nil {
		return fromError(traceID, err)
	}
	return outMessage{Status: "saved", CredentialID: pkg.CredentialID, Account: pkg.Account, TraceID: traceID}
}

func updateLogin(svc *logins.Service, origin string, req inMessage, traceID string) outMessage {
	if req.CredentialID == "" || req.Password == "" {
		return fail(traceID, "UA-BROWSER-002", "browser.validate", "credential_id and password are required.", "Retry from the Universal Auth menu.")
	}
	cur, out := offered(svc, origin, req.CredentialID, traceID)
	if cur == nil {
		return out
	}
	newResource := ""
	if req.SaveAs != "" {
		r, err := saveTarget(origin, req.SaveAs)
		if err != nil && req.SaveAs != cur.Resource {
			return fail(traceID, "UA-BROWSER-002", "browser.validate", err.Error(), "Pick one of the offered sites.")
		}
		if err == nil {
			newResource = r
		}
	}
	account := cur.Account
	if req.Account != "" {
		account = strings.TrimSpace(req.Account)
	}
	fields := map[string]string{"username": req.Username, "password": req.Password}
	pkg, err := svc.Update(context.Background(), req.CredentialID, newResource, account, fields, traceID)
	if err != nil {
		return approvalError(traceID, err)
	}
	return outMessage{Status: "updated", CredentialID: pkg.CredentialID, Account: pkg.Account, TraceID: traceID}
}

func deleteLogin(svc *logins.Service, origin string, req inMessage, traceID string) outMessage {
	cur, out := offered(svc, origin, req.CredentialID, traceID)
	if cur == nil {
		return out
	}
	if err := svc.Delete(context.Background(), req.CredentialID, traceID); err != nil {
		return approvalError(traceID, err)
	}
	return outMessage{Status: "deleted", CredentialID: req.CredentialID, TraceID: traceID}
}

func linkSite(svc *logins.Service, origin string, req inMessage, traceID string) outMessage {
	resource, err := vaultcrypto.NormalizeOrigin(req.Resource)
	if err != nil {
		return fail(traceID, "UA-BROWSER-002", "browser.validate", "Invalid site to link.", "Pick a saved login.")
	}
	if req.Type == "unlink_site" {
		err = svc.Aliases.Unlink(origin, resource)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		items, lerr := svc.Vault.ListResource(ctx, resource, vaultcrypto.KindLogin, traceID)
		cancel()
		if lerr != nil {
			return fromError(traceID, lerr)
		}
		if len(items) == 0 {
			return fail(traceID, "UA-VAULT-002", "vault.lookup", "No saved login for "+resource+".", "Pick a saved login.")
		}
		err = svc.Aliases.Link(origin, resource)
	}
	if err != nil {
		return fail(traceID, "UA-BROWSER-006", "browser.alias", err.Error(), "")
	}
	return outMessage{Status: "ok", TraceID: traceID}
}

func allLogins(svc *logins.Service, _ string, _ inMessage, traceID string) outMessage {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	items, err := svc.Vault.List(ctx, traceID)
	if err != nil {
		return fromError(traceID, err)
	}
	out := []loginMeta{}
	for _, m := range items {
		if m.Kind == vaultcrypto.KindLogin {
			out = append(out, loginMeta{CredentialID: m.CredentialID, Resource: m.Resource, Account: m.Account, UpdatedAt: m.UpdatedAt})
		}
	}
	return outMessage{Status: "ok", Logins: out, TraceID: traceID}
}

// offered returns the metadata of id if it is a login offered on origin.
func offered(svc *logins.Service, origin, id, traceID string) (*vault.CredentialMeta, outMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	matches, err := svc.Matches(ctx, origin, traceID)
	if err != nil {
		return nil, fromError(traceID, err)
	}
	for _, m := range matches {
		if m.CredentialID == id {
			meta := m.CredentialMeta
			return &meta, outMessage{}
		}
	}
	return nil, outcome("error", traceID, "UA-BROWSER-005", "browser.offered", logins.ErrNotOffered.Error(), "Pick a login listed for this site.")
}

func saveTarget(origin, saveAs string) (string, error) {
	targets, err := logins.SaveTargets(origin)
	if err != nil {
		return "", err
	}
	if saveAs == "" {
		return origin, nil
	}
	want, err := vaultcrypto.NormalizeOrigin(saveAs)
	if err != nil || !slices.Contains(targets, want) {
		return "", errors.New("logins from this page can only be saved for " + strings.Join(targets, ", "))
	}
	return want, nil
}

func toMeta(ms []logins.Match) []loginMeta {
	out := make([]loginMeta, 0, len(ms))
	for _, m := range ms {
		out = append(out, loginMeta{CredentialID: m.CredentialID, Resource: m.Resource, Account: m.Account, Match: m.Match, UpdatedAt: m.UpdatedAt})
	}
	return out
}

func approvalError(traceID string, err error) outMessage {
	fmt.Fprintf(os.Stderr, "[%s] approval: %v\n", traceID, err)
	msg := err.Error()
	switch {
	case errors.Is(err, vaultwrite.ErrDenied) || msg == "denied":
		return outcome("denied", traceID, "UA-RELEASE-003", "release.denied", "Denied on the Pixel.", "")
	case errors.Is(err, context.DeadlineExceeded) || msg == "timeout":
		o := outcome("timeout", traceID, "UA-RELEASE-002", "release.timeout", "Timed out waiting for Pixel approval.", "Try again.")
		o.Retryable = true
		return o
	}
	var exists *logins.ErrExists
	if errors.As(err, &exists) {
		return outcome("exists", traceID, "UA-VAULT-002", "vault.update", err.Error(), "Use a different account label.")
	}
	return fromError(traceID, err)
}

func diagnose(traceID string) outMessage {
	cfg, err := config.Load("")
	if err != nil {
		return fail(traceID, "UA-CONFIG-001", "diagnose.config", "Failed to load local configuration.", "Run 'authctl doctor'.")
	}
	return outMessage{
		Status: "ok", Code: "UA-BROWSER-000", Stage: "diagnose", TraceID: traceID,
		HostVersion: hostVersion, ProtocolVersion: protocolVersion, ConfigLoaded: true,
		VaultConfigured: cfg.VaultURL != "" && cfg.TrustedDevice.VaultKeyID != "",
		PixelPaired:     cfg.TrustedDevice.VaultKeyID != "",
	}
}

func fromError(traceID string, err error) outMessage {
	var apiErr *apierror.Error
	if errors.As(err, &apiErr) {
		t := apiErr.TraceID
		if t == "" {
			t = traceID
		}
		return outMessage{Status: "error", Code: apiErr.Code, Stage: apiErr.Stage, Error: apiErr.Message,
			TraceID: t, RequestID: apiErr.RequestID, Retryable: apiErr.Retryable, Action: apiErr.Action}
	}
	return fail(traceID, "UA-BROWSER-001", "browser.unknown", err.Error(), "Run 'authctl doctor'.")
}

func fail(traceID, code, stage, msg, action string) outMessage {
	return outcome("error", traceID, code, stage, msg, action)
}

func outcome(status, traceID, code, stage, msg, action string) outMessage {
	return outMessage{Status: status, Code: code, Stage: stage, Error: msg, TraceID: traceID, Action: action}
}

func generateTraceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
