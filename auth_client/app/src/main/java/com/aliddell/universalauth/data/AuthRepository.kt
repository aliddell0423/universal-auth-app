package com.aliddell.universalauth.data

import com.aliddell.universalauth.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

interface AuthRepository {
    suspend fun checkHealth(): Result<String>
    suspend fun getPendingRequests(): Result<List<AuthRequest>>
    suspend fun registerDevice(registration: DeviceRegistrationWithVault): Result<Unit>
    suspend fun getTrustedDesktop(): Result<TrustedDesktop>
    suspend fun submitSignedApproval(id: String, deviceId: String, signature: String): Result<AuthRequest>
    suspend fun submitReleaseResponse(id: String, response: ReleaseResponse): Result<AuthRequest>
    suspend fun submitDenial(id: String): Result<AuthRequest>
    suspend fun getRequest(id: String): Result<AuthRequest>
    suspend fun registerPushInstallation(registration: PushRegistration): Result<Unit>
}

/**
 * A delivery address for an already-trusted device. The installation ID is not
 * an identity: the Pixel's hardware-backed key fingerprint remains the only
 * trust anchor, and the broker rejects any device_id it does not already trust.
 */
@kotlinx.serialization.Serializable
data class PushRegistration(
    val device_id: String,
    val provider: String = "fcm",
    val installation_id: String
)

@kotlinx.serialization.Serializable
data class DeviceRegistrationWithVault(
    val device_id: String,
    val name: String,
    val algorithm: String,
    val public_key: String,
    val vault_key_id: String,
    val vault_algorithm: String,
    val vault_public_key: String
)

@kotlinx.serialization.Serializable
data class TrustedDesktop(
    val desktop_id: String,
    val name: String,
    val algorithm: String,
    val public_key: String
)

@kotlinx.serialization.Serializable
private data class SignedDecision(
    val decision: String,
    val device_id: String,
    val signature: String
)

class DefaultAuthRepository(
    private val client: OkHttpClient = OkHttpClient(),
    private val baseUrl: String = BuildConfig.BROKER_BASE_URL,
    private val token: String = BuildConfig.BROKER_TOKEN
) : AuthRepository {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    private val mediaType = "application/json".toMediaType()

    private fun handleError(responseCode: Int, bodyString: String, defaultStage: String): Nothing {
        val apiError = try {
            json.decodeFromString<ApiError>(bodyString)
        } catch (_: Exception) {
            null
        }
        if (apiError != null) {
            throw ApiException(apiError)
        }
        throw ApiException(
            ApiError(
                code = "UA-ANDROID-001",
                stage = defaultStage,
                message = "Request failed (HTTP $responseCode).",
                retryable = false,
                action = "Check the service and try again."
            )
        )
    }

    override suspend fun checkHealth(): Result<String> = withContext(Dispatchers.IO) {
        val request = Request.Builder().url("$baseUrl/healthz").build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.healthz")
                }
                response.body.string()
            }
        }
    }

    override suspend fun getPendingRequests(): Result<List<AuthRequest>> = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl/v1/requests/pending")
            .header("Authorization", "Bearer $token")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.list_pending")
                }
                val body = response.body.string()
                json.decodeFromString<List<AuthRequest>>(body)
            }
        }
    }

    override suspend fun registerDevice(
        registration: DeviceRegistrationWithVault
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(registration)
        val body = payload.toRequestBody(mediaType)
        val request = Request.Builder()
            .url("$baseUrl/v1/devices/register")
            .post(body)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.register_device")
                }
            }
        }
    }

    override suspend fun getTrustedDesktop(): Result<TrustedDesktop> = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl/v1/desktops/trusted")
            .header("Authorization", "Bearer $token")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.trusted_desktop")
                }
                val body = response.body.string()
                json.decodeFromString<TrustedDesktop>(body)
            }
        }
    }

    override suspend fun submitSignedApproval(
        id: String,
        deviceId: String,
        signature: String
    ): Result<AuthRequest> = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(SignedDecision("approved", deviceId, signature))
        val body = payload.toRequestBody(mediaType)
        val request = Request.Builder()
            .url("$baseUrl/v1/requests/$id/decision")
            .post(body)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.decision")
                }
                val responseBody = response.body.string()
                json.decodeFromString<AuthRequest>(responseBody)
            }
        }
    }

    override suspend fun submitReleaseResponse(
        id: String,
        response: ReleaseResponse
    ): Result<AuthRequest> = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(response)
        val body = payload.toRequestBody(mediaType)
        val request = Request.Builder()
            .url("$baseUrl/v1/requests/$id/release-response")
            .post(body)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.attach_release_response")
                }
                val responseBody = response.body.string()
                json.decodeFromString<AuthRequest>(responseBody)
            }
        }
    }

    override suspend fun getRequest(id: String): Result<AuthRequest> = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl/v1/requests/$id")
            .header("Authorization", "Bearer $token")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.request_fetch")
                }
                json.decodeFromString<AuthRequest>(response.body.string())
            }
        }
    }

    override suspend fun registerPushInstallation(
        registration: PushRegistration
    ): Result<Unit> = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(registration)
        val body = payload.toRequestBody(mediaType)
        val request = Request.Builder()
            .url("$baseUrl/v1/devices/push-registration")
            .put(body)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.push_registration")
                }
            }
        }
    }

    override suspend fun submitDenial(id: String): Result<AuthRequest> = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(Decision("denied"))
        val body = payload.toRequestBody(mediaType)
        val request = Request.Builder()
            .url("$baseUrl/v1/requests/$id/decision")
            .post(body)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val body = response.body.string()
                    handleError(response.code, body, "broker.decision")
                }
                val responseBody = response.body.string()
                json.decodeFromString<AuthRequest>(responseBody)
            }
        }
    }
}
