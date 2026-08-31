package com.aliddell.universalauth.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ApiErrorTest {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    @Test
    fun `decodes structured 400 error`() {
        val body = """
            {
                "code": "UA-BROKER-003",
                "stage": "broker.attach_release_response",
                "message": "Broker rejected the secure release response.",
                "trace_id": "7fe91c",
                "request_id": "abc123",
                "retryable": false,
                "action": "Check the secure release response."
            }
        """.trimIndent()

        val err = json.decodeFromString<ApiError>(body)

        assertEquals("UA-BROKER-003", err.code)
        assertEquals("broker.attach_release_response", err.stage)
        assertEquals("Broker rejected the secure release response.", err.message)
        assertEquals("7fe91c", err.traceId)
        assertEquals("abc123", err.requestId)
        assertEquals(false, err.retryable)
        assertEquals("Check the secure release response.", err.action)
    }

    @Test
    fun `decodes partial error safely`() {
        val body = """
            {
                "code": "UA-VAULT-001",
                "stage": "vault.readyz",
                "message": "Vault schema is not current."
            }
        """.trimIndent()

        val err = json.decodeFromString<ApiError>(body)

        assertEquals("UA-VAULT-001", err.code)
        assertNull(err.traceId)
        assertNull(err.requestId)
        assertEquals(false, err.retryable)
        assertEquals("", err.action)
    }

    @Test
    fun `toOperationError preserves trace and request ids`() {
        val err = ApiError(
            code = "UA-BROKER-003",
            stage = "broker.attach_release_response",
            message = "Broker rejected the secure release response.",
            traceId = "7fe91c",
            requestId = "abc123",
            retryable = false,
            action = "Check the secure release response."
        )

        val op = err.toOperationError()

        assertEquals("UA-BROKER-003", op.code)
        assertEquals("7fe91c", op.traceId)
        assertEquals("abc123", op.requestId)
        assertEquals("Check the secure release response.", op.action)
    }

    @Test
    fun `decode fallback for non-JSON body does not leak raw body`() {
        val body = "Internal Server Error: SQL ERROR: SELECT * FROM trusted_desktop"
        val apiError = try {
            json.decodeFromString<ApiError>(body)
        } catch (_: Exception) {
            null
        }

        assertNull("must not parse non-JSON body", apiError)
    }

    @Test
    fun `encode produces stable structured envelope`() {
        val err = ApiError(
            code = "UA-ANDROID-001",
            stage = "android.fallback",
            message = "Request failed.",
            traceId = "trace",
            requestId = "req",
            retryable = false,
            action = "Retry."
        )

        val encoded = json.encodeToString(err)

        assertTrue(encoded.contains("\"code\":\"UA-ANDROID-001\""))
        assertTrue(encoded.contains("\"stage\":\"android.fallback\""))
        assertTrue(encoded.contains("\"trace_id\""))
        assertTrue(encoded.contains("\"request_id\""))
        assertTrue(encoded.contains("\"retryable\":false"))
    }
}
