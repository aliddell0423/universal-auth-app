// Package push delivers "a request exists" notifications to a trusted device.
//
// Push delivery is a doorbell, not part of the authorization protocol. A
// notification carries only the request ID; the device must fetch the real
// request from the broker and the existing signed approval flow is unchanged.
// Consequently a push failure must never fail request creation.
package push

import "context"

// Payload field names sent to the device. Kept deliberately minimal: no
// challenge, credential package, signature, DEK, vault data, or token.
const (
	KeyType      = "type"
	KeyRequestID = "request_id"

	TypeCredentialRequest = "credential_request"
)

// Sender delivers a notification to a single device installation.
type Sender interface {
	// SendCredentialRequest tells the installation that requestID exists.
	SendCredentialRequest(ctx context.Context, installationID string, requestID string) error
}

// NopSender is used when push delivery is not configured. It succeeds without
// sending anything so the broker runs normally without Firebase credentials.
type NopSender struct{}

func (NopSender) SendCredentialRequest(context.Context, string, string) error { return nil }
