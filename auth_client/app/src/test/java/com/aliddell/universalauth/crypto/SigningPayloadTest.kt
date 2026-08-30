package com.aliddell.universalauth.crypto

import com.aliddell.universalauth.data.AuthRequest
import org.junit.Assert.assertEquals
import org.junit.Test

class SigningPayloadTest {
    @Test
    fun payloadMatchesGolden() {
        val request = AuthRequest(
            id = "0123456789abcdef",
            source = "andrew-fedora",
            kind = "test",
            resource = "development",
            message = "Please authenticate",
            challenge = "dGVzdC1jaGFsbGVuZ2U",
            clientNonce = "dGVzdC1jbGllbnQtbm9uY2U",
            status = "pending",
            createdAt = "2026-08-30T12:00:00Z"
        )
        val payload = buildSigningPayload(request, "approved")
        val golden = this::class.java.classLoader!!.getResourceAsStream("golden.txt")?.use { it.readAllBytes() }
            ?: throw IllegalStateException("golden.txt not found")
        assertEquals(String(golden, Charsets.UTF_8), String(payload, Charsets.UTF_8))
    }
}
