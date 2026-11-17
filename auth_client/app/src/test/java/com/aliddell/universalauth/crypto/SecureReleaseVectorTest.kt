package com.aliddell.universalauth.crypto

import com.aliddell.universalauth.data.ReleaseRequest
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

// Runs the Pixel side of a secure release against a request produced by the
// Go desktop agent (testdata/contracts/release_vector_v3.json), then opens the
// response the way the desktop does.
class SecureReleaseVectorTest {
    private val json = Json { ignoreUnknownKeys = true }

    private val vector: JsonObject = json.parseToJsonElement(
        javaClass.classLoader!!.getResourceAsStream("contracts/release_vector_v3.json")!!
            .bufferedReader().use { it.readText() }
    ).jsonObject

    private fun str(key: String) = vector[key]!!.jsonPrimitive.content

    private fun ecPrivate(key: String): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(str(key))))

    private fun pixelAgreement(): KeyAgreement =
        KeyAgreement.getInstance("ECDH").apply { init(ecPrivate("pixel_vault_private_key_pkcs8")) }

    private fun release(): ReleaseRequest = json.decodeFromJsonElement(vector["release_request"]!!)

    private fun process(release: ReleaseRequest, displayedResource: String = "ssh/vector") = SecureRelease.process(
        requestId = str("request_id"),
        challenge = str("challenge"),
        clientNonce = str("client_nonce"),
        displayedResource = displayedResource,
        release = release,
        pinnedDesktopId = str("desktop_id"),
        pinnedDesktopPublic = Base64.getDecoder().decode(str("desktop_public_key")),
        pinnedPixelVaultKeyId = str("pixel_vault_key_id"),
        vaultKeyAgreement = ::pixelAgreement
    )

    @Test
    fun `v3 release request from the desktop agent is released and decryptable`() {
        val release = release()
        val response = process(release)

        assertEquals(SecureRelease.PROTOCOL_V2, response.protocol)
        assertEquals("00112233445566778899aabbccddeeff", response.credentialId)
        assertEquals(release.packageHash, response.packageHash)

        // Desktop side, following desktop-agent/internal/release.
        val url = Base64.getUrlDecoder()
        val pixelEphemeral = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(url.decode(response.pixelEphemeralPublic)))
        val secret = KeyAgreement.getInstance("ECDH").run {
            init(ecPrivate("desktop_ephemeral_private_key_pkcs8"))
            doPhase(pixelEphemeral, true)
            generateSecret()
        }
        val bound = "request_id=${str("request_id")}\n" +
            "challenge=${str("challenge")}\n" +
            "client_nonce=${str("client_nonce")}\n" +
            "desktop_id=${str("desktop_id")}\n" +
            "credential_id=${response.credentialId}\n" +
            "resource=ssh/vector\n" +
            "package_hash=${response.packageHash}\n" +
            "pixel_vault_key_id=${response.pixelVaultKeyId}\n"
        val salt = MessageDigest.getInstance("SHA-256")
            .digest(("universal-auth:release-transfer-salt:v2\n$bound").toByteArray(StandardCharsets.UTF_8))
        val transferKey = HKDF.deriveSha256(
            secret, salt, "universal-auth:release-transfer-key:v2".toByteArray(StandardCharsets.US_ASCII), 32
        )
        val aad = ("universal-auth:release-dek:v2\n$bound" +
            "fedora_ephemeral_public_key=${release.desktopEphemeralPublic}\n" +
            "pixel_ephemeral_public_key=${response.pixelEphemeralPublic}\n").toByteArray(StandardCharsets.UTF_8)
        val dek = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(transferKey, "AES"), GCMParameterSpec(128, url.decode(response.transferNonce)))
            updateAAD(aad)
            doFinal(url.decode(response.encryptedDek))
        }
        assertArrayEquals(url.decode(str("expected_dek")), dek)
    }

    @Test
    fun `release is refused when the displayed resource differs from the package`() {
        try {
            process(release(), displayedResource = "ssh/something-harmless")
            fail("expected SecurityException")
        } catch (e: SecurityException) {
            assertEquals("displayed resource does not match the package being released", e.message)
        }
    }

    @Test
    fun `tampered package hash is rejected`() {
        try {
            process(release().copy(packageHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            fail("expected SecurityException")
        } catch (e: SecurityException) {
            assertEquals("package hash mismatch", e.message)
        }
    }

    @Test
    fun `signature over a different ephemeral key is rejected`() {
        val other = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(Base64.getDecoder().decode(str("desktop_public_key")))
        try {
            process(release().copy(desktopEphemeralPublic = other))
            fail("expected SecurityException")
        } catch (e: SecurityException) {
            assertEquals("invalid desktop signature", e.message)
        }
    }
}
