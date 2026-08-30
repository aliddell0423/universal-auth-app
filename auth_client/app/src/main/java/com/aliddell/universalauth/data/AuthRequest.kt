package com.aliddell.universalauth.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AuthRequest(
    val id: String,
    val source: String,
    val kind: String,
    val resource: String,
    val message: String,
    val challenge: String,
    @SerialName("client_nonce") val clientNonce: String,
    val status: String,
    @SerialName("created_at") val createdAt: String,
    @SerialName("decided_at") val decidedAt: String? = null
)
