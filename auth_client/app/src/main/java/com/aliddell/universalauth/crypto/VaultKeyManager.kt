package com.aliddell.universalauth.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.crypto.KeyAgreement

class VaultKeyManager(
    private val alias: String = "universal_auth_vault_key_v1"
) {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun isSupported(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    }

    fun ensureKey(): KeyPair {
        if (!isSupported()) {
            throw KeyManagerException("Secure release requires Android 12 (API 31) or later")
        }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        val keyPair = if (entry != null) {
            KeyPair(entry.certificate.publicKey, entry.privateKey)
        } else {
            createKeyPair()
        }
        if (!isHardwareBacked(keyPair.private)) {
            throw KeyManagerException("Vault key is not backed by secure hardware (StrongBox or TEE)")
        }
        return keyPair
    }

    fun publicKeyEncoded(): String {
        val keyPair = ensureKey()
        return Base64.getEncoder().encodeToString(keyPair.public.encoded)
    }

    fun keyId(): String {
        val keyPair = ensureKey()
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(keyPair.public.encoded).toLowercaseHex()
    }

    fun createKeyAgreement(): KeyAgreement {
        val keyPair = ensureKey()
        val agreement = KeyAgreement.getInstance("ECDH")
        try {
            agreement.init(keyPair.private)
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            throw KeyManagerException("User authentication required for vault key", e)
        }
        return agreement
    }

    private fun createKeyPair(): KeyPair {
        return try {
            generateWithStrongBox(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generateWithStrongBox(strongBox = false)
        } catch (e: InvalidAlgorithmParameterException) {
            if (e.cause is StrongBoxUnavailableException) {
                generateWithStrongBox(strongBox = false)
            } else {
                throw e
            }
        }
    }

    private fun generateWithStrongBox(strongBox: Boolean): KeyPair {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            throw KeyManagerException("PURPOSE_AGREE_KEY requires API 31")
        }
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_AGREE_KEY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setUserAuthenticationParameters(
                5,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        generator.initialize(builder.build())
        return generator.generateKeyPair()
    }

    private fun isHardwareBacked(privateKey: java.security.PrivateKey): Boolean {
        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        } else {
            keyInfo.isInsideSecureHardware
        }
    }

    private fun ByteArray.toLowercaseHex(): String {
        return joinToString("") { "%02x".format(it) }
    }
}
