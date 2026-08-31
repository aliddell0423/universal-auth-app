package com.aliddell.universalauth.data

import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ContractFixtureTest {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private fun load(name: String): String {
        return javaClass.classLoader!!.getResourceAsStream(name)!!
            .bufferedReader()
            .use { it.readText() }
    }

    @Test
    fun `release_response fixture round-trips all required fields`() {
        val body = load("contracts/release_response.json")
        val response = json.decodeFromString<ReleaseResponse>(body)

        assertEquals("universal-auth:secure-release:v1", response.protocol)
        assertEquals("cred-123", response.credentialId)
        assertEquals("hash-abc", response.packageHash)
        assertEquals("pixel-key-1", response.pixelVaultKeyId)
        assertEquals("e30", response.pixelEphemeralPublic)
        assertEquals("nonce123", response.transferNonce)
        assertEquals("encDek123", response.encryptedDek)

        val encoded = json.encodeToString(response)
        assertTrue("protocol", encoded.contains("\"protocol\":\"universal-auth:secure-release:v1\""))
        assertTrue("credential_id", encoded.contains("\"credential_id\":\"cred-123\""))
        assertTrue("package_hash", encoded.contains("\"package_hash\":\"hash-abc\""))
        assertTrue("pixel_vault_key_id", encoded.contains("\"pixel_vault_key_id\":\"pixel-key-1\""))
        assertTrue("pixel_ephemeral_public_key", encoded.contains("\"pixel_ephemeral_public_key\":\"e30\""))
        assertTrue("transfer_nonce", encoded.contains("\"transfer_nonce\":\"nonce123\""))
        assertTrue("encrypted_dek", encoded.contains("\"encrypted_dek\":\"encDek123\""))
    }

    @Test
    fun `missing protocol fixture fails to decode`() {
        val body = load("contracts/failure_cases/missing_protocol.json")
        try {
            json.decodeFromString<ReleaseResponse>(body)
            fail("expected decoding to fail without protocol")
        } catch (_: SerializationException) {
            // expected
        }
    }

    @Test
    fun `api_error fixture decodes with all fields`() {
        val body = load("contracts/api_error.json")
        val err = json.decodeFromString<ApiError>(body)

        assertEquals("UA-BROKER-003", err.code)
        assertEquals("broker.attach_release_response", err.stage)
        assertEquals("Broker rejected the secure release response.", err.message)
        assertEquals("trace-7fe91c", err.traceId)
        assertEquals("req-abc123", err.requestId)
        assertFalse(err.retryable)
        assertEquals("Check the secure release response.", err.action)

        val op = err.toOperationError()
        assertEquals("UA-BROKER-003", op.code)
        assertEquals("trace-7fe91c", op.traceId)
        assertEquals("req-abc123", op.requestId)
    }

    @Test
    fun `malformed server body does not decode as ApiError`() {
        val body = load("contracts/failure_cases/malformed_api_error.json")
        try {
            json.decodeFromString<ApiError>(body)
            fail("expected malformed body to fail")
        } catch (_: SerializationException) {
            // expected
        }
    }

    @Test
    fun `broker_request fixture preserves trace and request ids`() {
        val body = load("contracts/broker_request.json")
        val request = json.decodeFromString<AuthRequest>(body)

        assertEquals("req-abc123", request.id)
        assertEquals("trace-7fe91c", request.traceId)
        assertEquals("pending", request.status)
    }
}
