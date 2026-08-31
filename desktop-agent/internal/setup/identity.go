package setup

import (
	"context"
	"errors"
	"fmt"

	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/apierror"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/broker"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/config"
	"github.com/aliddell0423/universal-auth-app/desktop-agent/internal/identity"
)

// runIdentityAndRegistration ensures a desktop identity exists and is trusted
// by the broker. It never replaces an existing trusted desktop.
func (r *Report) runIdentityAndRegistration(
	ctx context.Context,
	opts Options,
	cfg *config.Config,
	cfgPath string,
	client *broker.Client,
) {
	identPath := opts.IdentityPath

	ident, err := identity.Load(identPath)
	switch {
	case err == nil:
		r.add(Step{Name: "desktop identity", Status: Pass,
			Message: fmt.Sprintf("Desktop identity %s", short(ident.DesktopID()))})
	case opts.CheckOnly:
		r.add(Step{Name: "desktop identity", Status: Action,
			Message: "Desktop identity would be created.",
			Detail:  "Run 'authctl setup' without --check to create it."})
		r.add(Step{Name: "desktop registered", Status: Skip, Message: "No desktop identity yet."})
		return
	default:
		ident, err = identity.LoadOrCreate(identPath)
		if err != nil {
			r.add(Step{Name: "desktop identity", Status: Fail, Code: "UA-CONFIG-006",
				Message: "Could not create desktop identity.", Detail: err.Error()})
			r.add(Step{Name: "desktop registered", Status: Skip, Message: "No desktop identity."})
			return
		}
		r.add(Step{Name: "desktop identity", Status: Create,
			Message: fmt.Sprintf("Created desktop identity %s", short(ident.DesktopID()))})
	}

	fetchCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	existing, err := client.GetTrustedDesktop(fetchCtx, "")
	if err == nil {
		if existing.DesktopID != ident.DesktopID() {
			r.add(Step{Name: "desktop trust conflict", Status: Fail, Code: "UA-SETUP-004",
				Message: "The broker already trusts a different desktop.",
				Detail: fmt.Sprintf(
					"Broker trusts:  desktop_id = %s\nThis machine:   desktop_id = %s\nUniversal Auth will not replace trusted identity automatically.",
					existing.DesktopID, ident.DesktopID())})
			return
		}
		if existing.PublicKey != ident.PublicKey() {
			r.add(Step{Name: "desktop trust conflict", Status: Fail, Code: "UA-SETUP-005",
				Message: "The broker trusts this desktop id with a different public key.",
				Detail:  "Universal Auth will not replace trusted identity automatically."})
			return
		}
		r.add(Step{Name: "desktop registered", Status: Pass,
			Message: fmt.Sprintf("Broker trusts this desktop (%s).", short(existing.DesktopID))})
		return
	}

	// A 404 means no desktop is registered yet; anything else is a real error.
	if !isNotRegistered(err) {
		r.add(Step{Name: "desktop registered", Status: Fail, Code: "UA-BROKER-004",
			Message: "Could not read the trusted desktop.", Detail: err.Error()})
		return
	}

	if opts.CheckOnly {
		r.add(Step{Name: "desktop registered", Status: Action,
			Message: "This desktop would be registered.",
			Detail:  "Run 'authctl setup' without --check to register."})
		return
	}

	name := opts.DesktopName
	if name == "" {
		name = "Fedora Desktop"
	}

	regCtx, regCancel := context.WithTimeout(ctx, requestTimeout)
	defer regCancel()

	if err := client.RegisterDesktop(regCtx, broker.TrustedDesktop{
		DesktopID: ident.DesktopID(),
		Name:      name,
		Algorithm: "ECDSA_P256_SHA256",
		PublicKey: ident.PublicKey(),
	}, ""); err != nil {
		r.add(Step{Name: "desktop registered", Status: Fail, Code: "UA-BROKER-005",
			Message: "Could not register this desktop.", Detail: err.Error()})
		return
	}
	r.add(Step{Name: "desktop registered", Status: Create,
		Message: fmt.Sprintf("Registered %s (%s).", name, short(ident.DesktopID()))})
}

func isNotRegistered(err error) bool {
	var apiErr *apierror.Error
	if errors.As(err, &apiErr) {
		return apiErr.Code == "UA-BROKER-002"
	}
	return false
}

func short(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:16] + "..."
}
