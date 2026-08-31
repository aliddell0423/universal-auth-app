package doctor

import (
	"context"
	"fmt"
	"time"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
)

func checkBroker(ctx context.Context, cfg *config.Config, client *broker.Client) []Result {
	var out []Result
	if client == nil {
		out = append(out, newResult("Broker", "ready", Skip, "", "Cannot check broker without URL and token.", ""))
		out = append(out, newResult("Broker", "trusted Pixel", Skip, "", "Broker not reachable.", ""))
		out = append(out, newResult("Broker", "Pixel identity matches local pin", Skip, "", "Broker not reachable.", ""))
		out = append(out, newResult("Broker", "Pixel approval key matches local pin", Skip, "", "Broker not reachable.", ""))
		out = append(out, newResult("Broker", "Pixel vault key matches local pin", Skip, "", "Broker not reachable.", ""))
		out = append(out, newResult("Broker", "trusted desktop", Skip, "", "Broker not reachable.", ""))
		out = append(out, newResult("Broker", "desktop identity matches local identity", Skip, "", "Broker not reachable.", ""))
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ready(ctx); err != nil {
		out = append(out, newResult("Broker", "ready", Fail, "UA-BROKER-009", fmt.Sprintf("Broker is not ready: %v.", err), "Verify the broker is running and the data volume is mounted."))
		out = append(out, newResult("Broker", "trusted Pixel", Skip, "", "Broker not ready.", ""))
		out = append(out, newResult("Broker", "Pixel identity matches local pin", Skip, "", "Broker not ready.", ""))
		out = append(out, newResult("Broker", "Pixel approval key matches local pin", Skip, "", "Broker not ready.", ""))
		out = append(out, newResult("Broker", "Pixel vault key matches local pin", Skip, "", "Broker not ready.", ""))
		out = append(out, newResult("Broker", "trusted desktop", Skip, "", "Broker not ready.", ""))
		out = append(out, newResult("Broker", "desktop identity matches local identity", Skip, "", "Broker not ready.", ""))
		return out
	}
	out = append(out, newResult("Broker", "ready", Pass, "", "Broker /readyz returned 200.", ""))

	td, err := client.GetTrustedDevice(ctx, "")
	if err != nil {
		apiErr := extractAPIError(err)
		if apiErr != nil {
			out = append(out, newResult("Broker", "trusted Pixel", Fail, apiErr.Code, apiErr.Message, apiErr.Action))
		} else {
			out = append(out, newResult("Broker", "trusted Pixel", Fail, "UA-BROKER-004", err.Error(), "Check broker /v1/devices/trusted."))
		}
		out = append(out, newResult("Broker", "Pixel identity matches local pin", Skip, "", "Trusted Pixel not available.", ""))
		out = append(out, newResult("Broker", "Pixel approval key matches local pin", Skip, "", "Trusted Pixel not available.", ""))
		out = append(out, newResult("Broker", "Pixel vault key matches local pin", Skip, "", "Trusted Pixel not available.", ""))
		out = append(out, newResult("Broker", "trusted desktop", Skip, "", "Trusted Pixel not available.", ""))
		out = append(out, newResult("Broker", "desktop identity matches local identity", Skip, "", "Trusted Pixel not available.", ""))
		return out
	}
	out = append(out, newResult("Broker", "trusted Pixel", Pass, "", fmt.Sprintf("Trusted Pixel: %s.", td.DeviceID), ""))

	if td.DeviceID != cfg.TrustedDevice.DeviceID {
		out = append(out, newResult("Broker", "Pixel identity matches local pin", Fail, "UA-BROKER-001", fmt.Sprintf("Broker device id %s does not match local pin %s.", td.DeviceID, cfg.TrustedDevice.DeviceID), "Run 'authctl pair' again with the correct Pixel."))
	} else {
		out = append(out, newResult("Broker", "Pixel identity matches local pin", Pass, "", "Broker device fingerprint matches local pin.", ""))
	}

	if td.PublicKey != cfg.TrustedDevice.PublicKey {
		out = append(out, newResult("Broker", "Pixel approval key matches local pin", Fail, "UA-BROKER-001", "Broker approval public key differs from local pin.", "Run 'authctl pair' again."))
	} else {
		out = append(out, newResult("Broker", "Pixel approval key matches local pin", Pass, "", "Broker approval public key matches local pin.", ""))
	}

	if td.VaultKeyID != cfg.TrustedDevice.VaultKeyID {
		out = append(out, newResult("Broker", "Pixel vault key matches local pin", Fail, "UA-BROKER-001", fmt.Sprintf("Broker vault key id %s does not match local pin %s.", td.VaultKeyID, cfg.TrustedDevice.VaultKeyID), "Run 'authctl pair' again."))
	} else {
		out = append(out, newResult("Broker", "Pixel vault key matches local pin", Pass, "", "Broker vault key id matches local pin.", ""))
	}

	if td.VaultPublicKey != cfg.TrustedDevice.VaultPubKey {
		out = append(out, newResult("Broker", "Pixel vault public key matches local pin", Fail, "UA-BROKER-001", "Broker vault public key differs from local pin.", "Run 'authctl pair' again."))
	} else {
		out = append(out, newResult("Broker", "Pixel vault public key matches local pin", Pass, "", "Broker vault public key matches local pin.", ""))
	}

	bd, err := client.GetTrustedDesktop(ctx, "")
	if err != nil {
		apiErr := extractAPIError(err)
		if apiErr != nil {
			out = append(out, newResult("Broker", "trusted desktop", Fail, apiErr.Code, apiErr.Message, apiErr.Action))
		} else {
			out = append(out, newResult("Broker", "trusted desktop", Fail, "UA-BROKER-004", err.Error(), "Check broker /v1/desktops/trusted."))
		}
		out = append(out, newResult("Broker", "desktop identity matches local identity", Skip, "", "Trusted desktop not available.", ""))
		return out
	}
	out = append(out, newResult("Broker", "trusted desktop", Pass, "", fmt.Sprintf("Trusted desktop: %s.", bd.DesktopID), ""))

	ident, err := identity.LoadOrCreate("")
	if err != nil {
		out = append(out, newResult("Broker", "desktop identity matches local identity", Fail, "UA-CONFIG-006", fmt.Sprintf("Cannot load desktop identity: %v.", err), "Recreate the desktop identity."))
		return out
	}
	if bd.DesktopID != ident.DesktopID() {
		out = append(out, newResult("Broker", "desktop identity matches local identity", Fail, "UA-BROKER-002", fmt.Sprintf("Broker desktop id %s does not match local desktop id %s.", bd.DesktopID, ident.DesktopID()), "Run 'authctl desktop-register' with the correct desktop."))
	} else if bd.PublicKey != ident.PublicKey() {
		out = append(out, newResult("Broker", "desktop identity matches local identity", Fail, "UA-BROKER-002", "Broker desktop public key differs from local public key.", "Run 'authctl desktop-register' again."))
	} else {
		out = append(out, newResult("Broker", "desktop identity matches local identity", Pass, "", "Broker desktop matches local identity.", ""))
	}
	return out
}
