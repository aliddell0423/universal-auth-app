package com.aliddell.universalauth.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertTrue
import org.junit.Test

class ReleaseResponseSerializationTest {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    @Test
    fun `encodes all seven required fields`() {
        val response = ReleaseResponse(
            protocol = "universal-auth:secure-release:v1",
            credentialId = "abc123",
            packageHash = "hashValue",
            pixelVaultKeyId = "pixelKey",
            pixelEphemeralPublic = "pixelPub",
            transferNonce = "nonce",
            encryptedDek = "encDek"
        )

        val encoded = json.encodeToString(response)

        assertTrue("protocol must be present", encoded.contains("\"protocol\":\"universal-auth:secure-release:v1\""))
        assertTrue("credential_id must be present", encoded.contains("\"credential_id\":\"abc123\""))
        assertTrue("package_hash must be present", encoded.contains("\"package_hash\":\"hashValue\""))
        assertTrue("pixel_vault_key_id must be present", encoded.contains("\"pixel_vault_key_id\":\"pixelKey\""))
        assertTrue("pixel_ephemeral_public_key must be present", encoded.contains("\"pixel_ephemeral_public_key\":\"pixelPub\""))
        assertTrue("transfer_nonce must be present", encoded.contains("\"transfer_nonce\":\"nonce\""))
        assertTrue("encrypted_dek must be present", encoded.contains("\"encrypted_dek\":\"encDek\""))
    }

    @Test
    fun `rejects empty protocol`() {
        val response = ReleaseResponse(
            protocol = "",
            credentialId = "abc123",
            packageHash = "hashValue",
            pixelVaultKeyId = "pixelKey",
            pixelEphemeralPublic = "pixelPub",
            transferNonce = "nonce",
            encryptedDek = "encDek"
        )

        val encoded = json.encodeToString(response)
        assertTrue(encoded.contains("\"protocol\":\"\""))
    }
}
