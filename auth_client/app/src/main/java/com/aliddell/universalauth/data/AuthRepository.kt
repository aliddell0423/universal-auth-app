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
    suspend fun submitDecision(id: String, decision: String): Result<AuthRequest>
}

class DefaultAuthRepository(
    private val client: OkHttpClient = OkHttpClient(),
    private val baseUrl: String = BuildConfig.BROKER_BASE_URL,
    private val token: String = BuildConfig.BROKER_TOKEN
) : AuthRepository {
    private val json = Json { ignoreUnknownKeys = true }
    private val mediaType = "application/json".toMediaType()

    override suspend fun checkHealth(): Result<String> = withContext(Dispatchers.IO) {
        val request = Request.Builder().url("$baseUrl/healthz").build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) throw Exception("HTTP ${response.code}")
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
                if (!response.isSuccessful) throw Exception("HTTP ${response.code}")
                val body = response.body.string()
                json.decodeFromString<List<AuthRequest>>(body)
            }
        }
    }

    override suspend fun submitDecision(id: String, decision: String): Result<AuthRequest> = withContext(Dispatchers.IO) {
        val payload = json.encodeToString(Decision(decision))
        val body = payload.toRequestBody(mediaType)
        val request = Request.Builder()
            .url("$baseUrl/v1/requests/$id/decision")
            .post(body)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .build()
        runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) throw Exception("HTTP ${response.code}")
                val responseBody = response.body.string()
                json.decodeFromString<AuthRequest>(responseBody)
            }
        }
    }
}
