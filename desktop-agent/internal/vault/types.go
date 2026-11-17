package vault

// CredentialMeta mirrors the vault-service list response. It contains no
// secret material.
type CredentialMeta struct {
	CredentialID    string `json:"credential_id"`
	Kind            string `json:"kind"`
	Resource        string `json:"resource"`
	PixelVaultKeyID string `json:"pixel_vault_key_id"`
	CryptoVersion   int    `json:"crypto_version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}
