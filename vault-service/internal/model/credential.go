package model

// CredentialPackage is the v2 encrypted credential package stored by the server.
type CredentialPackage struct {
	CredentialID           string `json:"credential_id"`
	Origin                 string `json:"origin"`
	Ciphertext             string `json:"ciphertext"`
	CipherNonce            string `json:"cipher_nonce"`
	WrappedDEK             string `json:"wrapped_dek"`
	WrapNonce              string `json:"wrap_nonce"`
	WrapEphemeralPublicKey string `json:"wrap_ephemeral_public_key"`
	PixelVaultKeyID        string `json:"pixel_vault_key_id"`
	CryptoVersion          int    `json:"crypto_version"`
}

// CredentialMeta is returned by list/exists endpoints; it never contains secrets.
type CredentialMeta struct {
	CredentialID    string `json:"credential_id"`
	Origin          string `json:"origin"`
	PixelVaultKeyID string `json:"pixel_vault_key_id"`
	CryptoVersion   int    `json:"crypto_version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// CredentialPackageInput is the POST body for creating a v2 package.
type CredentialPackageInput struct {
	CredentialID           string `json:"credential_id"`
	Origin                 string `json:"origin"`
	Ciphertext             string `json:"ciphertext"`
	CipherNonce            string `json:"cipher_nonce"`
	WrappedDEK             string `json:"wrapped_dek"`
	WrapNonce              string `json:"wrap_nonce"`
	WrapEphemeralPublicKey string `json:"wrap_ephemeral_public_key"`
	PixelVaultKeyID        string `json:"pixel_vault_key_id"`
	CryptoVersion          int    `json:"crypto_version"`
}
