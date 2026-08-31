package setup

import (
	"context"
	"errors"
	"fmt"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/apierror"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
)

// runPixelPairing detects the Pixel pairing state and pins the trusted device
// metadata locally. A missing Pixel is a remaining human ACTION, not a failure.
func (r *Report) runPixelPairing(
	ctx context.Context,
	opts Options,
	cfg *config.Config,
	cfgPath string,
	client *broker.Client,
) {
	fetchCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	td, err := client.GetTrustedDevice(fetchCtx, "")
	if err != nil {
		if isNoPixel(err) {
			r.add(Step{Name: "pixel paired", Status: Action,
				Message: "Pixel still needs pairing.",
				Detail:  "Open the Universal Auth app on your Pixel, then run 'authctl pair --expected-device-id <id>'."})
			return
		}
		r.add(Step{Name: "pixel paired", Status: Fail, Code: "UA-BROKER-004",
			Message: "Could not read the trusted Pixel.", Detail: err.Error()})
		return
	}

	// Refuse to silently replace an already-pinned but different Pixel.
	pinned := cfg.TrustedDevice
	if pinned.DeviceID != "" && pinned.DeviceID != td.DeviceID {
		r.add(Step{Name: "pixel trust conflict", Status: Fail, Code: "UA-SETUP-009",
			Message: "The broker trusts a different Pixel than the one pinned locally.",
			Detail: fmt.Sprintf(
				"Broker trusts:  device_id = %s\nLocally pinned: device_id = %s\nUniversal Auth will not replace trusted identity automatically.",
				td.DeviceID, pinned.DeviceID)})
		return
	}

	desired := config.TrustedDevice{
		DeviceID:    td.DeviceID,
		Name:        td.Name,
		Algorithm:   td.Algorithm,
		PublicKey:   td.PublicKey,
		VaultKeyID:  td.VaultKeyID,
		VaultAlgo:   td.VaultAlgorithm,
		VaultPubKey: td.VaultPublicKey,
	}

	if pinned == desired {
		r.add(Step{Name: "pixel paired", Status: Pass,
			Message: fmt.Sprintf("Pixel %s is paired.", short(td.DeviceID))})
		return
	}

	if opts.CheckOnly {
		r.add(Step{Name: "pixel paired", Status: Action,
			Message: "Pixel trust metadata would be pinned locally.",
			Detail:  "Run 'authctl setup' without --check to pin it."})
		return
	}

	cfg.TrustedDevice = desired
	if err := cfg.Save(cfgPath); err != nil {
		r.add(Step{Name: "pixel paired", Status: Fail, Code: "UA-SETUP-003",
			Message: "Could not write the Pixel trust metadata.", Detail: err.Error()})
		return
	}
	if pinned.DeviceID == "" {
		r.add(Step{Name: "pixel paired", Status: Create,
			Message: fmt.Sprintf("Pinned Pixel %s.", short(td.DeviceID))})
		return
	}
	r.add(Step{Name: "pixel paired", Status: Update,
		Message: fmt.Sprintf("Refreshed Pixel %s metadata.", short(td.DeviceID))})
}

func isNoPixel(err error) bool {
	var apiErr *apierror.Error
	if errors.As(err, &apiErr) {
		return apiErr.Code == "UA-BROKER-001"
	}
	return false
}
