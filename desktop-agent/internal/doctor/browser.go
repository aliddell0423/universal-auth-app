package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/nm"
)

type manifest struct {
	Name              string   `json:"name"`
	Type              string   `json:"type"`
	Path              string   `json:"path"`
	AllowedExtensions []string `json:"allowed_extensions"`
}

type diagnoseResponse struct {
	Status          string `json:"status"`
	Code            string `json:"code,omitempty"`
	Message         string `json:"message,omitempty"`
	HostVersion     string `json:"host_version"`
	ProtocolVersion int    `json:"protocol_version"`
	ConfigLoaded    bool   `json:"config_loaded"`
	VaultConfigured bool   `json:"vault_configured"`
	PixelPaired     bool   `json:"pixel_paired"`
	Error           string `json:"error,omitempty"`
}

func checkBrowser() []Result {
	var out []Result

	home, err := os.UserHomeDir()
	if err != nil {
		out = append(out, newResult("Browser", "native messaging manifest", Fail, "UA-BROWSER-002", "Cannot determine home directory.", ""))
		out = append(out, newResult("Browser", "manifest name", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest type", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest allowed extension", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest points to installed host", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host executable exists", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}

	manifestPath := filepath.Join(home, ".mozilla", "native-messaging-hosts", "com.aliddell.universalauth.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			out = append(out, newResult("Browser", "native messaging manifest", Fail, "UA-BROWSER-002", fmt.Sprintf("Native messaging manifest not found at %s.", manifestPath), "Run the browser extension install script."))
		} else {
			out = append(out, newResult("Browser", "native messaging manifest", Fail, "UA-BROWSER-002", fmt.Sprintf("Cannot read manifest: %v.", err), "Check manifest permissions."))
		}
		out = append(out, newResult("Browser", "manifest name", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest type", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest allowed extension", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest points to installed host", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host executable exists", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}
	out = append(out, newResult("Browser", "native messaging manifest", Pass, "", fmt.Sprintf("Manifest found at %s.", manifestPath), ""))

	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		out = append(out, newResult("Browser", "manifest name", Fail, "UA-BROWSER-002", "Manifest is not valid JSON.", "Reinstall the browser extension."))
		out = append(out, newResult("Browser", "manifest type", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest allowed extension", Skip, "", "", ""))
		out = append(out, newResult("Browser", "manifest points to installed host", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host executable exists", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}

	if m.Name != "com.aliddell.universalauth" {
		out = append(out, newResult("Browser", "manifest name", Fail, "UA-BROWSER-002", fmt.Sprintf("Manifest name is %q, expected %q.", m.Name, "com.aliddell.universalauth"), "Reinstall the browser extension."))
	} else {
		out = append(out, newResult("Browser", "manifest name", Pass, "", "Manifest name is correct.", ""))
	}

	if m.Type != "stdio" {
		out = append(out, newResult("Browser", "manifest type", Fail, "UA-BROWSER-002", fmt.Sprintf("Manifest type is %q, expected %q.", m.Type, "stdio"), "Reinstall the browser extension."))
	} else {
		out = append(out, newResult("Browser", "manifest type", Pass, "", "Manifest type is stdio.", ""))
	}

	if !contains(m.AllowedExtensions, "universal-auth@aliddell.dev") {
		out = append(out, newResult("Browser", "manifest allowed extension", Fail, "UA-BROWSER-002", "Manifest does not allow the Universal Auth extension.", "Reinstall the browser extension."))
	} else {
		out = append(out, newResult("Browser", "manifest allowed extension", Pass, "", "Extension is allowed.", ""))
	}

	if m.Path == "" {
		out = append(out, newResult("Browser", "manifest points to installed host", Fail, "UA-BROWSER-002", "Manifest does not specify a host path.", "Reinstall the browser extension."))
		out = append(out, newResult("Browser", "host executable exists", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}
	out = append(out, newResult("Browser", "manifest points to installed host", Pass, "", fmt.Sprintf("Manifest path: %s.", m.Path), ""))

	info, err := os.Stat(m.Path)
	if err != nil {
		if os.IsNotExist(err) {
			out = append(out, newResult("Browser", "host executable exists", Fail, "UA-BROWSER-003", fmt.Sprintf("Host executable not found at %s.", m.Path), "Build and install the ua-browser-host binary."))
		} else {
			out = append(out, newResult("Browser", "host executable exists", Fail, "UA-BROWSER-003", fmt.Sprintf("Cannot stat host executable: %v.", err), "Check host executable permissions."))
		}
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		out = append(out, newResult("Browser", "host executable exists", Fail, "UA-BROWSER-003", fmt.Sprintf("Host at %s is not executable.", m.Path), "chmod +x the host executable."))
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}
	out = append(out, newResult("Browser", "host executable exists", Pass, "", fmt.Sprintf("Host executable found at %s.", m.Path), ""))

	resp, err := runNativeHostDiagnostic(m.Path)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			out = append(out, newResult("Browser", "host diagnostic handshake", Fail, "UA-BROWSER-001", "Native host diagnostic timed out.", "Verify the host binary is not hung."))
		} else {
			out = append(out, newResult("Browser", "host diagnostic handshake", Fail, "UA-BROWSER-001", fmt.Sprintf("Native host diagnostic failed: %v.", err), "Verify the host binary and manifest."))
		}
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}
	if resp.Status == "error" {
		out = append(out, newResult("Browser", "host diagnostic handshake", Fail, coalesce(resp.Code, "UA-BROWSER-001"), coalesce(resp.Message, resp.Error, "Native host reported an error during diagnostic."), "Check the host configuration."))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}
	out = append(out, newResult("Browser", "host diagnostic handshake", Pass, "", fmt.Sprintf("Host status: %s, config loaded: %v, pixel paired: %v.", resp.Status, resp.ConfigLoaded, resp.PixelPaired), ""))

	if resp.ProtocolVersion != 2 {
		out = append(out, newResult("Browser", "host protocol version", Fail, "UA-BROWSER-005", fmt.Sprintf("Host protocol version is %d, expected 2.", resp.ProtocolVersion), "Update the ua-browser-host binary to the current version."))
	} else {
		out = append(out, newResult("Browser", "host protocol version", Pass, "", "Host protocol version is 2.", ""))
	}
	return out
}

func runNativeHostDiagnostic(path string) (*diagnoseResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() { _, _ = io.Copy(io.Discard, stderr) }()

	msg := map[string]string{"type": "diagnose"}
	if err := nm.WriteMessage(stdin, msg); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}
	_ = stdin.Close()

	var resp diagnoseResponse
	if err := nm.ReadMessage(stdout, &resp); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}

	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return &resp, nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
