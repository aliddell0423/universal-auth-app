package com.aliddell.universalauth.crypto

import com.aliddell.universalauth.data.ReleaseRequest
import com.aliddell.universalauth.data.ReleaseResponse
import com.aliddell.universalauth.data.ReleaseStage
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object SecureRelease {
    data class Package(
        val credentialId: String,
        val origin: String,
        val ciphertext: ByteArray,
        val cipherNonce: ByteArray,
        val wrappedDek: ByteArray,
        val wrapNonce: ByteArray,
        val wrapEphemeralPublic: ByteArray,
        val pixelVaultKeyId: String,
        val cryptoVersion: Int
    )

    data class PlaintextCredential(
        val username: String,
        val password: String
    )

    fun process(
        requestId: String,
        challenge: String,
        clientNonce: String,
        release: ReleaseRequest,
        pinnedDesktopId: String,
        pinnedDesktopPublic: ByteArray,
        pinnedPixelVaultKeyId: String,
        vaultKeyManager: VaultKeyManager,
        onStage: (ReleaseStage) -> Unit = {}
    ): ReleaseResponse {
        onStage(ReleaseStage.VALIDATING_REQUEST)
        if (release.protocol != "universal-auth:secure-release:v1") {
            throw SecurityException("unsupported protocol")
        }
        if (release.desktopAlgorithm != "ECDSA_P256_SHA256") {
            throw SecurityException("unsupported desktop algorithm")
        }
        if (release.desktopId != pinnedDesktopId) {
            throw SecurityException("desktop not trusted")
        }
        onStage(ReleaseStage.VERIFYING_DESKTOP)

        val pkg = parsePackage(release.credentialPackage)
        if (pkg.cryptoVersion != 2) {
            throw SecurityException("unsupported credential crypto version")
        }
        val computedHash = packageHash(pkg)
        if (computedHash != release.packageHash) {
            throw SecurityException("package hash mismatch")
        }
        if (pkg.pixelVaultKeyId != pinnedPixelVaultKeyId) {
            throw SecurityException("pixel vault key id mismatch")
        }
        onStage(ReleaseStage.VERIFYING_PACKAGE)

        val desktopPublic = decodeP256PublicKey(pinnedDesktopPublic)
        val signedPayload = canonicalReleaseRequest(
            requestId, challenge, clientNonce, release.desktopId,
            "credential_release", pkg.origin, pkg.credentialId, release.packageHash,
            release.desktopEphemeralPublic, pkg.pixelVaultKeyId
        )
        val sig = Base64.getDecoder().decode(release.desktopSignature)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(desktopPublic)
        verifier.update(signedPayload)
        if (!verifier.verify(sig)) {
            throw SecurityException("invalid desktop signature")
        }

        val wrapPublic = decodeP256PublicKey(pkg.wrapEphemeralPublic)
        val desktopReleasePublic = decodeP256PublicKey(Base64.getUrlDecoder().decode(release.desktopEphemeralPublic))

        onStage(ReleaseStage.UNLOCKING_VAULT_KEY)
        val agreement = vaultKeyManager.createKeyAgreement()
        agreement.doPhase(wrapPublic, true)
        val shared = agreement.generateSecret()

        val wrapSalt = wrapSalt(pkg.credentialId, pkg.origin, pkg.pixelVaultKeyId)
        val wrapKey = HKDF.deriveSha256(
            shared, wrapSalt,
            "universal-auth:vault-wrap-key:v2".toByteArray(StandardCharsets.US_ASCII), 32
        )

        onStage(ReleaseStage.UNWRAPPING_DEK)
        val dek = aesGcmDecrypt(wrapKey, pkg.wrappedDek, pkg.wrapNonce, wrapAAD(pkg))
        if (dek.size != 32) {
            throw SecurityException("dek length is ${dek.size}, want 32")
        }

        onStage(ReleaseStage.PREPARING_TRANSFER)
        val responseKeyPair = generateResponseKeyPair()
        val responseAgreement = KeyAgreement.getInstance("ECDH")
        responseAgreement.init(responseKeyPair.private)
        responseAgreement.doPhase(desktopReleasePublic, true)
        val transferSecret = responseAgreement.generateSecret()

        val transferSalt = transferSalt(
            requestId, challenge, clientNonce, release.desktopId,
            pkg.credentialId, pkg.origin, release.packageHash, pkg.pixelVaultKeyId
        )
        val transferKey = HKDF.deriveSha256(
            transferSecret, transferSalt,
            "universal-auth:release-transfer-key:v1".toByteArray(StandardCharsets.US_ASCII), 32
        )

        val transferNonce = randomBytes(12)
        val pixelEphemeralPublic = base64url(responseKeyPair.public.encoded)
        val aad = transferAAD(
            requestId, challenge, clientNonce, release.desktopId,
            pkg.credentialId, pkg.origin, release.packageHash, pkg.pixelVaultKeyId,
            release.desktopEphemeralPublic, pixelEphemeralPublic
        )
        val encryptedDek = aesGcmEncrypt(transferKey, dek, transferNonce, aad)

        onStage(ReleaseStage.COMPLETE)
        return ReleaseResponse(
            protocol = "universal-auth:secure-release:v1",
            credentialId = pkg.credentialId,
            packageHash = release.packageHash,
            pixelVaultKeyId = pkg.pixelVaultKeyId,
            pixelEphemeralPublic = pixelEphemeralPublic,
            transferNonce = base64url(transferNonce),
            encryptedDek = base64url(encryptedDek)
        )
    }

    fun decryptCredential(pkg: Package, dek: ByteArray): PlaintextCredential {
        val plaintext = aesGcmDecrypt(dek, pkg.ciphertext, pkg.cipherNonce, credentialAAD(pkg))
        val json = String(plaintext, StandardCharsets.UTF_8)
        val username = jsonField(json, "username")
        val password = jsonField(json, "password")
        return PlaintextCredential(username, password)
    }

    private fun parsePackage(s: String): Package {
        val lines = s.trimEnd().split("\n")
        if (lines.isEmpty() || lines[0] != "universal-auth:vault-package:v2") {
            throw SecurityException("invalid package header")
        }
        val map = lines.drop(1).associate { line ->
            val idx = line.indexOf('=')
            if (idx < 0) throw SecurityException("invalid package line: $line")
            line.substring(0, idx) to line.substring(idx + 1)
        }
        val credentialId = String(base64urlDecode(map["credential_id"] ?: throw SecurityException("missing credential_id")), StandardCharsets.UTF_8)
        val origin = String(base64urlDecode(map["origin"] ?: throw SecurityException("missing origin")), StandardCharsets.UTF_8)
        return Package(
            credentialId = credentialId,
            origin = origin,
            ciphertext = base64urlDecode(map["ciphertext"] ?: throw SecurityException("missing ciphertext")),
            cipherNonce = base64urlDecode(map["cipher_nonce"] ?: throw SecurityException("missing cipher_nonce")),
            wrappedDek = base64urlDecode(map["wrapped_dek"] ?: throw SecurityException("missing wrapped_dek")),
            wrapNonce = base64urlDecode(map["wrap_nonce"] ?: throw SecurityException("missing wrap_nonce")),
            wrapEphemeralPublic = base64urlDecode(map["wrap_ephemeral_public_key"] ?: throw SecurityException("missing wrap_ephemeral_public_key")),
            pixelVaultKeyId = map["pixel_vault_key_id"] ?: throw SecurityException("missing pixel_vault_key_id"),
            cryptoVersion = (map["crypto_version"] ?: throw SecurityException("missing crypto_version")).toInt()
        )
    }

    private fun canonicalPackage(pkg: Package): ByteArray {
        val sb = StringBuilder()
        sb.append("universal-auth:vault-package:v2\n")
        sb.append("credential_id=${base64urlUtf8(pkg.credentialId)}\n")
        sb.append("origin=${base64urlUtf8(pkg.origin)}\n")
        sb.append("ciphertext=${base64url(pkg.ciphertext)}\n")
        sb.append("cipher_nonce=${base64url(pkg.cipherNonce)}\n")
        sb.append("wrapped_dek=${base64url(pkg.wrappedDek)}\n")
        sb.append("wrap_nonce=${base64url(pkg.wrapNonce)}\n")
        sb.append("wrap_ephemeral_public_key=${base64url(pkg.wrapEphemeralPublic)}\n")
        sb.append("pixel_vault_key_id=${pkg.pixelVaultKeyId}\n")
        sb.append("crypto_version=${pkg.cryptoVersion}\n")
        return sb.toString().toByteArray(StandardCharsets.UTF_8)
    }

    private fun packageHash(pkg: Package): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(canonicalPackage(pkg))
        return base64url(hash)
    }

    private fun canonicalReleaseRequest(
        requestId: String,
        challenge: String,
        clientNonce: String,
        desktopId: String,
        kind: String,
        origin: String,
        credentialId: String,
        packageHash: String,
        desktopEphemeralPublic: String,
        pixelVaultKeyId: String
    ): ByteArray {
        val sb = StringBuilder()
        sb.append("universal-auth:secure-release-request:v1\n")
        sb.append("request_id=${base64urlUtf8(requestId)}\n")
        sb.append("challenge=${challenge}\n")
        sb.append("client_nonce=${clientNonce}\n")
        sb.append("desktop_id=${desktopId}\n")
        sb.append("kind=${base64urlUtf8(kind)}\n")
        sb.append("origin=${base64urlUtf8(origin)}\n")
        sb.append("credential_id=${base64urlUtf8(credentialId)}\n")
        sb.append("package_hash=${packageHash}\n")
        sb.append("desktop_ephemeral_public_key=${desktopEphemeralPublic}\n")
        sb.append("pixel_vault_key_id=${pixelVaultKeyId}\n")
        return sb.toString().toByteArray(StandardCharsets.UTF_8)
    }

    private fun wrapSalt(credentialId: String, origin: String, pixelVaultKeyId: String): ByteArray {
        val s = "universal-auth:vault-wrap-salt:v2\ncredential_id=$credentialId\norigin=$origin\npixel_vault_key_id=$pixelVaultKeyId\n"
        return MessageDigest.getInstance("SHA-256").digest(s.toByteArray(StandardCharsets.UTF_8))
    }

    private fun wrapAAD(pkg: Package): ByteArray {
        val s = "universal-auth:vault-dek:v2\ncredential_id=${pkg.credentialId}\norigin=${pkg.origin}\npixel_vault_key_id=${pkg.pixelVaultKeyId}\nwrap_ephemeral_public_key=${base64url(pkg.wrapEphemeralPublic)}\n"
        return s.toByteArray(StandardCharsets.UTF_8)
    }

    private fun transferSalt(
        requestId: String,
        challenge: String,
        clientNonce: String,
        desktopId: String,
        credentialId: String,
        origin: String,
        packageHash: String,
        pixelVaultKeyId: String
    ): ByteArray {
        val s = """universal-auth:release-transfer-salt:v1
request_id=$requestId
challenge=$challenge
client_nonce=$clientNonce
desktop_id=$desktopId
credential_id=$credentialId
origin=$origin
package_hash=$packageHash
pixel_vault_key_id=$pixelVaultKeyId
"""
        return MessageDigest.getInstance("SHA-256").digest(s.toByteArray(StandardCharsets.UTF_8))
    }

    private fun transferAAD(
        requestId: String,
        challenge: String,
        clientNonce: String,
        desktopId: String,
        credentialId: String,
        origin: String,
        packageHash: String,
        pixelVaultKeyId: String,
        fedoraEphemeralPublic: String,
        pixelEphemeralPublic: String
    ): ByteArray {
        val s = """universal-auth:release-dek:v1
request_id=$requestId
challenge=$challenge
client_nonce=$clientNonce
desktop_id=$desktopId
credential_id=$credentialId
origin=$origin
package_hash=$packageHash
pixel_vault_key_id=$pixelVaultKeyId
fedora_ephemeral_public_key=$fedoraEphemeralPublic
pixel_ephemeral_public_key=$pixelEphemeralPublic
"""
        return s.toByteArray(StandardCharsets.UTF_8)
    }

    private fun credentialAAD(pkg: Package): ByteArray {
        val s = "universal-auth:vault-credential:v2\ncredential_id=${pkg.credentialId}\norigin=${pkg.origin}\npixel_vault_key_id=${pkg.pixelVaultKeyId}\n"
        return s.toByteArray(StandardCharsets.UTF_8)
    }

    private fun aesGcmDecrypt(key: ByteArray, ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    private fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun decodeP256PublicKey(der: ByteArray): PublicKey {
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePublic(X509EncodedKeySpec(der))
    }

    private fun generateResponseKeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        return gen.generateKeyPair()
    }

    private fun base64urlUtf8(s: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(StandardCharsets.UTF_8))

    private fun base64url(b: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun base64urlDecode(s: String): ByteArray =
        Base64.getUrlDecoder().decode(s)

    private fun randomBytes(n: Int): ByteArray {
        val b = ByteArray(n)
        java.security.SecureRandom().nextBytes(b)
        return b
    }

    private fun jsonField(json: String, key: String): String {
        val pattern = """"$key"\s*:\s*"([^"]*)"""".toRegex()
        return pattern.find(json)?.groupValues?.get(1) ?: ""
    }
}
