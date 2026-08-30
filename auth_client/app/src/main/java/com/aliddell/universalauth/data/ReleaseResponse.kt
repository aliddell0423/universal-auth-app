package com.aliddell.universalauth.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ReleaseResponse(
    val protocol: String = "universal-auth:secure-release:v1",
    @SerialName("credential_id") val credentialId: String,
    @SerialName("package_hash") val packageHash: String,
    @SerialName("pixel_vault_key_id") val pixelVaultKeyId: String,
    @SerialName("pixel_ephemeral_public_key") val pixelEphemeralPublic: String,
    @SerialName("transfer_nonce") val transferNonce: String,
    @SerialName("encrypted_dek") val encryptedDek: String
)
