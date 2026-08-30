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

class ApprovalKeyManager(
    private val alias: String = "universal_auth_approval_key_v1"
) {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun ensureKey(): KeyPair {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        val keyPair = if (entry != null) {
            KeyPair(entry.certificate.publicKey, entry.privateKey)
        } else {
            createKeyPair()
        }
        if (!isHardwareBacked(keyPair.private)) {
            throw KeyManagerException("Approval key is not backed by secure hardware (StrongBox or TEE)")
        }
        return keyPair
    }

    fun publicKeyEncoded(): String {
        val keyPair = ensureKey()
        return Base64.getEncoder().encodeToString(keyPair.public.encoded)
    }

    fun deviceId(): String {
        val keyPair = ensureKey()
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(keyPair.public.encoded).toLowercaseHex()
    }

    fun createSignature(): Signature {
        val keyPair = ensureKey()
        return try {
            Signature.getInstance("SHA256withECDSA").apply {
                initSign(keyPair.private)
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyManagerException(
                "Approval key was invalidated, likely because biometrics changed. " +
                "Restart the broker and re-register this device.",
                e
            )
        }
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
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(0)
        }

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

class KeyManagerException(message: String, cause: Throwable? = null) : Exception(message, cause)
