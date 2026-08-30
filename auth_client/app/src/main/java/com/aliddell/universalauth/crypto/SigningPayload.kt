package com.aliddell.universalauth.crypto

import com.aliddell.universalauth.data.AuthRequest
import java.util.Base64

fun buildSigningPayload(request: AuthRequest, decision: String): ByteArray {
    val builder = StringBuilder()
    builder.append("universal-auth:v2\n")
    builder.append("request_id=").append(b64url(request.id)).append("\n")
    builder.append("challenge=").append(request.challenge).append("\n")
    builder.append("client_nonce=").append(request.clientNonce).append("\n")
    builder.append("decision=").append(b64url(decision)).append("\n")
    builder.append("source=").append(b64url(request.source)).append("\n")
    builder.append("kind=").append(b64url(request.kind)).append("\n")
    builder.append("resource=").append(b64url(request.resource)).append("\n")
    builder.append("message=").append(b64url(request.message)).append("\n")
    return builder.toString().toByteArray(Charsets.UTF_8)
}

private fun b64url(s: String): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
}
