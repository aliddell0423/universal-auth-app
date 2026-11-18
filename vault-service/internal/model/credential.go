package model

// CredentialPackage is the encrypted credential package stored by the server.
// v2 packages use Origin; v3 packages use Kind and Resource.
type CredentialPackage struct {
	CredentialID           string `json:"credential_id"`
	Kind                   string `json:"kind,omitempty"`
	Resource               string `json:"resource,omitempty"`
	Account                string `json:"account,omitempty"`
	Origin                 string `json:"origin,omitempty"`
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
	Kind            string `json:"kind"`
	Resource        string `json:"resource"`
	Account         string `json:"account"`
	PixelVaultKeyID string `json:"pixel_vault_key_id"`
	CryptoVersion   int    `json:"crypto_version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// CredentialPackageInput is the POST body for creating a package (v2 or v3).
type CredentialPackageInput struct {
	CredentialID           string `json:"credential_id"`
	Kind                   string `json:"kind"`
	Resource               string `json:"resource"`
	Account                string `json:"account,omitempty"`
	Origin                 string `json:"origin"`
	Ciphertext             string `json:"ciphertext"`
	CipherNonce            string `json:"cipher_nonce"`
	WrappedDEK             string `json:"wrapped_dek"`
	WrapNonce              string `json:"wrap_nonce"`
	WrapEphemeralPublicKey string `json:"wrap_ephemeral_public_key"`
	PixelVaultKeyID        string `json:"pixel_vault_key_id"`
	CryptoVersion          int    `json:"crypto_version"`
}

// MaxAccountLen bounds the account label, which is stored as plaintext
// metadata so the account picker works without a release.
const MaxAccountLen = 256
