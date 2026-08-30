package com.aliddell.universalauth.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ReleaseRequest(
    val protocol: String,
    @SerialName("desktop_id") val desktopId: String,
    @SerialName("desktop_algorithm") val desktopAlgorithm: String,
    @SerialName("desktop_ephemeral_public_key") val desktopEphemeralPublic: String,
    @SerialName("credential_package") val credentialPackage: String,
    @SerialName("package_hash") val packageHash: String,
    @SerialName("desktop_signature") val desktopSignature: String
)
