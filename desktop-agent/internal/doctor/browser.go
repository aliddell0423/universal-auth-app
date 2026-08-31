package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/nm"
)

type manifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

type diagnoseResponse struct {
	Status          string `json:"status"`
	HostVersion     string `json:"host_version"`
	ProtocolVersion int    `json:"protocol_version"`
	ConfigLoaded    bool   `json:"config_loaded"`
	VaultConfigured bool   `json:"vault_configured"`
	PixelPaired     bool   `json:"pixel_paired"`
	Error           string `json:"error,omitempty"`
	Code            string `json:"code,omitempty"`
}

func checkBrowser() []Result {
	var out []Result

	home, err := os.UserHomeDir()
	if err != nil {
		out = append(out, newResult("Browser", "native messaging manifest", Fail, "UA-BROWSER-002", "Cannot determine home directory.", ""))
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
		out = append(out, newResult("Browser", "manifest points to installed host", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host executable exists", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
	}
	out = append(out, newResult("Browser", "native messaging manifest exists", Pass, "", fmt.Sprintf("Manifest found at %s.", manifestPath), ""))

	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		out = append(out, newResult("Browser", "manifest valid", Fail, "UA-BROWSER-002", fmt.Sprintf("Manifest is not valid JSON: %v.", err), "Reinstall the browser extension."))
		out = append(out, newResult("Browser", "host executable exists", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host diagnostic handshake", Skip, "", "", ""))
		out = append(out, newResult("Browser", "host protocol version", Skip, "", "", ""))
		return out
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
		out = append(out, newResult("Browser", "host diagnostic handshake", Fail, "UA-BROWSER-001", fmt.Sprintf("Native host diagnostic failed: %v.", err), "Verify the host binary and manifest."))
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
	cmd := exec.Command(path)
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

	// Consume any stderr in case it helps with debugging, but do not block.
	go func() { _, _ = io.Copy(io.Discard, stderr) }()

	msg := map[string]string{"type": "diagnose"}
	if err := nm.WriteMessage(stdin, msg); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	_ = stdin.Close()

	var resp diagnoseResponse
	if err := nm.ReadMessage(stdout, &resp); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	_ = cmd.Wait()
	return &resp, nil
}
