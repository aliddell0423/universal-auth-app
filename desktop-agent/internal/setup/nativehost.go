package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	nativeHostName    = "com.aliddell.universalauth"
	nativeHostBinary  = "ua-browser-host"
	allowedExtensions = "universal-auth@aliddell.dev"
)

type nativeManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedExtensions []string `json:"allowed_extensions"`
}

// runNativeHost installs or updates the Firefox native messaging host and
// manifest. It is idempotent: an already-correct install reports PASS.
func (r *Report) runNativeHost(opts Options) {
	if opts.SkipNativeHost {
		r.add(Step{Name: "native host", Status: Skip, Message: "Skipped by request."})
		r.add(Step{Name: "firefox manifest", Status: Skip, Message: "Skipped by request."})
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		r.add(Step{Name: "native host", Status: Fail, Code: "UA-SETUP-006",
			Message: "Could not determine the home directory.", Detail: err.Error()})
		return
	}

	binDir := filepath.Join(home, ".local", "bin")
	hostPath := filepath.Join(binDir, nativeHostBinary)
	manifestDir := filepath.Join(home, ".mozilla", "native-messaging-hosts")
	manifestPath := filepath.Join(manifestDir, nativeHostName+".json")

	hostInstalled := isExecutable(hostPath)
	manifestOK := manifestMatches(manifestPath, hostPath)

	if opts.CheckOnly {
		if hostInstalled {
			r.add(Step{Name: "native host", Status: Pass, Message: fmt.Sprintf("Installed at %s.", hostPath)})
		} else {
			r.add(Step{Name: "native host", Status: Action,
				Message: "Native host would be built and installed.",
				Detail:  "Run 'authctl setup' without --check to install."})
		}
		if manifestOK {
			r.add(Step{Name: "firefox manifest", Status: Pass, Message: fmt.Sprintf("Installed at %s.", manifestPath)})
		} else {
			r.add(Step{Name: "firefox manifest", Status: Action,
				Message: "Firefox manifest would be written.",
				Detail:  "Run 'authctl setup' without --check to install."})
		}
		return
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		r.add(Step{Name: "native host", Status: Fail, Code: "UA-SETUP-006",
			Message: "Could not create ~/.local/bin.", Detail: err.Error()})
		return
	}

	// Always rebuild so an updated protocol version reaches the installed host.
	if err := buildNativeHost(hostPath); err != nil {
		if hostInstalled {
			r.add(Step{Name: "native host", Status: Fail, Code: "UA-SETUP-007",
				Message: "Could not rebuild the native host.", Detail: err.Error()})
			return
		}
		r.add(Step{Name: "native host", Status: Fail, Code: "UA-SETUP-007",
			Message: "Could not build the native host.", Detail: err.Error()})
		return
	}
	if hostInstalled {
		r.add(Step{Name: "native host", Status: Update, Message: fmt.Sprintf("Rebuilt %s.", hostPath)})
	} else {
		r.add(Step{Name: "native host", Status: Create, Message: fmt.Sprintf("Installed %s.", hostPath)})
	}

	if err := os.MkdirAll(manifestDir, 0o755); err != nil {
		r.add(Step{Name: "firefox manifest", Status: Fail, Code: "UA-SETUP-008",
			Message: "Could not create the native-messaging-hosts directory.", Detail: err.Error()})
		return
	}

	manifest := nativeManifest{
		Name:              nativeHostName,
		Description:       "Universal Auth browser bridge",
		Path:              hostPath,
		Type:              "stdio",
		AllowedExtensions: []string{allowedExtensions},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		r.add(Step{Name: "firefox manifest", Status: Fail, Code: "UA-SETUP-008",
			Message: "Could not encode the manifest.", Detail: err.Error()})
		return
	}
	data = append(data, '\n')
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		r.add(Step{Name: "firefox manifest", Status: Fail, Code: "UA-SETUP-008",
			Message: "Could not write the manifest.", Detail: err.Error()})
		return
	}
	if manifestOK {
		r.add(Step{Name: "firefox manifest", Status: Pass, Message: fmt.Sprintf("Manifest current at %s.", manifestPath)})
	} else {
		r.add(Step{Name: "firefox manifest", Status: Create, Message: fmt.Sprintf("Wrote %s.", manifestPath)})
	}
}

// buildNativeHost compiles the native host from the desktop-agent module.
func buildNativeHost(outPath string) error {
	moduleDir, err := findModuleDir()
	if err != nil {
		return err
	}
	cmd := exec.Command("go", "build", "-o", outPath, "./cmd/ua-browser-host")
	cmd.Dir = moduleDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

// findModuleDir walks upward looking for the desktop-agent go.mod so setup works
// from any working directory inside the repository.
func findModuleDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "cmd", "ua-browser-host")); err == nil {
				return dir, nil
			}
		}
		candidate := filepath.Join(dir, "desktop-agent")
		if _, err := os.Stat(filepath.Join(candidate, "cmd", "ua-browser-host")); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate the desktop-agent module from the current directory")
		}
		dir = parent
	}
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && info.Mode()&0111 != 0
}

func manifestMatches(manifestPath, hostPath string) bool {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return false
	}
	var m nativeManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	if m.Name != nativeHostName || m.Type != "stdio" || m.Path != hostPath {
		return false
	}
	for _, e := range m.AllowedExtensions {
		if e == allowedExtensions {
			return true
		}
	}
	return false
}
