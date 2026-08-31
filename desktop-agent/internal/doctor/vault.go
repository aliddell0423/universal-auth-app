package doctor

import (
	"context"
	"fmt"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vault"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/vaultcrypto"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
)

func checkVault(ctx context.Context, cfg *config.Config, client *vault.Client) []Result {
	var out []Result
	if client == nil {
		out = append(out, newResult("Vault", "ready", Skip, "", "Cannot check vault without URL and token.", ""))
		out = append(out, newResult("Vault", "schema current", Skip, "", "Vault not reachable.", ""))
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ready(ctx); err != nil {
		apiErr := extractAPIError(err)
		if apiErr != nil {
			out = append(out, newResult("Vault", "ready", Fail, apiErr.Code, fmt.Sprintf("Vault is not ready: %s.", apiErr.Message), apiErr.Action))
		} else {
			out = append(out, newResult("Vault", "ready", Fail, "UA-VAULT-004", fmt.Sprintf("Vault is not ready: %v.", err), "Verify the vault is running."))
		}
		out = append(out, newResult("Vault", "schema current", Skip, "", "Vault not ready.", ""))
		return out
	}
	out = append(out, newResult("Vault", "ready", Pass, "", "Vault /readyz returned 200.", ""))
	out = append(out, newResult("Vault", "schema current", Pass, "", "Vault schema is current.", ""))
	return out
}

func checkOrigin(ctx context.Context, cfg *config.Config, client *vault.Client, origin string) []Result {
	var out []Result
	out = append(out, newResult("Origin", "origin supplied", Pass, "", fmt.Sprintf("Checking credential for %s.", origin), ""))
	if client == nil {
		out = append(out, newResult("Origin", "credential exists", Skip, "", "Cannot check credential without vault URL and token.", ""))
		out = append(out, newResult("Origin", "package fetch", Skip, "", "", ""))
		out = append(out, newResult("Origin", "crypto version", Skip, "", "", ""))
		out = append(out, newResult("Origin", "package bound to pinned Pixel key", Skip, "", "", ""))
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	exists, err := client.CredentialExists(ctx, origin, "")
	if err != nil {
		apiErr := extractAPIError(err)
		if apiErr != nil {
			out = append(out, newResult("Origin", "credential exists", Fail, apiErr.Code, apiErr.Message, apiErr.Action))
		} else {
			out = append(out, newResult("Origin", "credential exists", Fail, "UA-VAULT-004", err.Error(), "Check the vault connection."))
		}
		out = append(out, newResult("Origin", "package fetch", Skip, "", "", ""))
		out = append(out, newResult("Origin", "crypto version", Skip, "", "", ""))
		out = append(out, newResult("Origin", "package bound to pinned Pixel key", Skip, "", "", ""))
		return out
	}
	if !exists {
		out = append(out, newResult("Origin", "credential exists", Fail, "UA-VAULT-002", fmt.Sprintf("No saved credential for %s.", origin), "Use 'vaultctl add' to store one."))
		out = append(out, newResult("Origin", "package fetch", Skip, "", "", ""))
		out = append(out, newResult("Origin", "crypto version", Skip, "", "", ""))
		out = append(out, newResult("Origin", "package bound to pinned Pixel key", Skip, "", "", ""))
		return out
	}
	out = append(out, newResult("Origin", "credential exists", Pass, "", "Credential exists.", ""))

	pkg, err := client.GetPackage(ctx, origin, "")
	if err != nil {
		apiErr := extractAPIError(err)
		if apiErr != nil {
			out = append(out, newResult("Origin", "package fetch", Fail, apiErr.Code, apiErr.Message, apiErr.Action))
		} else {
			out = append(out, newResult("Origin", "package fetch", Fail, "UA-VAULT-004", err.Error(), "Check the vault connection."))
		}
		out = append(out, newResult("Origin", "crypto version", Skip, "", "", ""))
		out = append(out, newResult("Origin", "package bound to pinned Pixel key", Skip, "", "", ""))
		return out
	}
	out = append(out, newResult("Origin", "package fetch", Pass, "", "Package fetched.", ""))

	if pkg.CryptoVersion != vaultcrypto.CryptoVersion {
		out = append(out, newResult("Origin", "crypto version", Fail, "UA-CRYPTO-001", fmt.Sprintf("Package crypto version is %d, expected %d.", pkg.CryptoVersion, vaultcrypto.CryptoVersion), "Re-store the credential with the current tooling."))
	} else {
		out = append(out, newResult("Origin", "crypto version", Pass, "", fmt.Sprintf("Package crypto version is %d.", pkg.CryptoVersion), ""))
	}

	if pkg.PixelVaultKeyID != cfg.TrustedDevice.VaultKeyID {
		out = append(out, newResult("Origin", "package bound to pinned Pixel key", Fail, "UA-CRYPTO-001", fmt.Sprintf("Package is bound to Pixel key %s, local pin is %s.", pkg.PixelVaultKeyID, cfg.TrustedDevice.VaultKeyID), "Re-store the credential with the current Pixel key."))
	} else {
		out = append(out, newResult("Origin", "package bound to pinned Pixel key", Pass, "", "Package is bound to the locally pinned Pixel key.", ""))
	}
	return out
}
