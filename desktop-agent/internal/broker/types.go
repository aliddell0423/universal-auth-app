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
	ID              string           `json:"id"`
	Source          string           `json:"source"`
	Kind            string           `json:"kind"`
	Resource        string           `json:"resource"`
	Message         string           `json:"message"`
	Challenge       string           `json:"challenge"`
	ClientNonce     string           `json:"client_nonce"`
	Status          string           `json:"status"`
	CreatedAt       time.Time        `json:"created_at"`
	DecidedAt       *time.Time       `json:"decided_at,omitempty"`
	ApprovalProof   *ApprovalProof   `json:"approval_proof,omitempty"`
	ReleaseRequest  *ReleaseRequest  `json:"release_request,omitempty"`
	ReleaseResponse *ReleaseResponse `json:"release_response,omitempty"`
}

type ApprovalProof struct {
	DeviceID  string `json:"device_id"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

type ReleaseRequest struct {
	Protocol               string `json:"protocol"`
	DesktopID              string `json:"desktop_id"`
	DesktopAlgorithm       string `json:"desktop_algorithm"`
	DesktopEphemeralPublic string `json:"desktop_ephemeral_public_key"`
	CredentialPackage      string `json:"credential_package"`
	PackageHash            string `json:"package_hash"`
	DesktopSignature       string `json:"desktop_signature"`
}

type ReleaseResponse struct {
	Protocol             string `json:"protocol"`
	CredentialID         string `json:"credential_id"`
	PackageHash          string `json:"package_hash"`
	PixelVaultKeyID      string `json:"pixel_vault_key_id"`
	PixelEphemeralPublic string `json:"pixel_ephemeral_public_key"`
	TransferNonce        string `json:"transfer_nonce"`
	EncryptedDEK         string `json:"encrypted_dek"`
}

type TrustedDevice struct {
	DeviceID       string `json:"device_id"`
	Name           string `json:"name"`
	Algorithm      string `json:"algorithm"`
	PublicKey      string `json:"public_key"`
	VaultKeyID     string `json:"vault_key_id"`
	VaultAlgorithm string `json:"vault_algorithm"`
	VaultPublicKey string `json:"vault_public_key"`
}

type TrustedDesktop struct {
	DesktopID string `json:"desktop_id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}
