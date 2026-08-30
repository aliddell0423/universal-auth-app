package broker

import "time"

type CreateRequest struct {
	Source      string `json:"source"`
	Kind        string `json:"kind"`
	Resource    string `json:"resource"`
	Message     string `json:"message"`
	ClientNonce string `json:"client_nonce"`
}

type Request struct {
	ID            string         `json:"id"`
	Source        string         `json:"source"`
	Kind          string         `json:"kind"`
	Resource      string         `json:"resource"`
	Message       string         `json:"message"`
	Challenge     string         `json:"challenge"`
	ClientNonce   string         `json:"client_nonce"`
	Status        string         `json:"status"`
	CreatedAt     time.Time      `json:"created_at"`
	DecidedAt     *time.Time     `json:"decided_at,omitempty"`
	ApprovalProof *ApprovalProof `json:"approval_proof,omitempty"`
}

type ApprovalProof struct {
	DeviceID  string `json:"device_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

type TrustedDevice struct {
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}
