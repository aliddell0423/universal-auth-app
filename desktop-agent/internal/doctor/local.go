package doctor

import (
	"fmt"
	"os"
	"strings"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
)

func checkLocal(cfg *config.Config) []Result {
	var out []Result

	path := config.DefaultPath()
	_, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			out = append(out, newResult("Local", "config readable", Fail, "UA-CONFIG-001", fmt.Sprintf("Config file not found at %s.", path), "Run 'authctl pair' to create one."))
			return out
		}
		out = append(out, newResult("Local", "config readable", Fail, "UA-CONFIG-001", fmt.Sprintf("Cannot read config file: %v.", err), "Check permissions or run 'authctl pair'."))
		return out
	}
	out = append(out, newResult("Local", "config readable", Pass, "", "Config file is readable.", ""))

	if cfg == nil {
		out = append(out, newResult("Local", "config version", Fail, "UA-CONFIG-001", "Config is not loaded.", "Run 'authctl pair'."))
		return out
	}
	out = append(out, newResult("Local", "config version", Pass, "", fmt.Sprintf("Config version is %d.", cfg.ConfigVersion), ""))

	if cfg.BrokerURL == "" {
		out = append(out, newResult("Local", "broker URL", Fail, "UA-CONFIG-003", "broker_url is not configured.", "Run 'authctl pair' or edit the config."))
	} else {
		out = append(out, newResult("Local", "broker URL", Pass, "", fmt.Sprintf("broker_url is %s.", cfg.BrokerURL), ""))
	}

	if cfg.VaultURL == "" {
		out = append(out, newResult("Local", "vault URL", Fail, "UA-CONFIG-002", "vault_url is not configured.", "Set vault_url in the config."))
	} else {
		out = append(out, newResult("Local", "vault URL", Pass, "", fmt.Sprintf("vault_url is %s.", cfg.VaultURL), ""))
	}

	brokerTokenPath := config.TokenPath()
	_, err = config.LoadBrokerToken()
	if err != nil {
		if isNotExist(err) {
			out = append(out, newResult("Local", "broker token", Fail, "UA-CONFIG-007", fmt.Sprintf("Broker token not found at %s.", brokerTokenPath), "Run 'authctl pair' or set BROKER_TOKEN."))
		} else if isPermissionError(err) {
			out = append(out, newResult("Local", "broker token", Fail, "UA-CONFIG-005", fmt.Sprintf("Broker token file %s has overly permissive permissions.", brokerTokenPath), filePermFix(brokerTokenPath)))
		} else {
			out = append(out, newResult("Local", "broker token", Fail, "UA-CONFIG-007", err.Error(), "Set BROKER_TOKEN or create the token file."))
		}
	} else {
		out = append(out, newResult("Local", "broker token", Pass, "", "Broker token is available and has safe permissions.", ""))
	}

	vaultTokenPath := config.VaultTokenPath()
	_, err = config.LoadVaultToken()
	if err != nil {
		if isNotExist(err) {
			out = append(out, newResult("Local", "vault token", Fail, "UA-CONFIG-005", fmt.Sprintf("Vault token not found at %s.", vaultTokenPath), "Run 'authctl pair' or set VAULT_TOKEN."))
		} else if isPermissionError(err) {
			out = append(out, newResult("Local", "vault token", Fail, "UA-CONFIG-005", fmt.Sprintf("Vault token file %s has overly permissive permissions.", vaultTokenPath), filePermFix(vaultTokenPath)))
		} else {
			out = append(out, newResult("Local", "vault token", Fail, "UA-CONFIG-005", err.Error(), "Set VAULT_TOKEN or create the token file."))
		}
	} else {
		out = append(out, newResult("Local", "vault token", Pass, "", "Vault token is available and has safe permissions.", ""))
	}

	ident, err := identity.LoadOrCreate("")
	if err != nil {
		out = append(out, newResult("Local", "desktop identity", Fail, "UA-CONFIG-006", fmt.Sprintf("Cannot load desktop identity: %v.", err), "Recreate the desktop identity."))
	} else {
		out = append(out, newResult("Local", "desktop identity", Pass, "", fmt.Sprintf("Desktop identity fingerprint: %s.", ident.DesktopID()), ""))
	}

	if cfg.TrustedDevice.VaultKeyID == "" {
		out = append(out, newResult("Local", "Pixel vault key pinned", Fail, "UA-CONFIG-004", "Pixel vault key is not paired.", "Run 'authctl pair'."))
	} else {
		out = append(out, newResult("Local", "Pixel vault key pinned", Pass, "", fmt.Sprintf("Pixel vault key is pinned: %s.", cfg.TrustedDevice.VaultKeyID), ""))
	}

	return out
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	return os.IsPermission(err) || strings.Contains(err.Error(), "overly permissive")
}
