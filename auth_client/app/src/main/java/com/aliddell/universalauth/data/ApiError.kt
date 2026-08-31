package com.aliddell.universalauth.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ApiError(
    val code: String,
    val stage: String,
    val message: String,
    @SerialName("trace_id")
    val traceId: String? = null,
    @SerialName("request_id")
    val requestId: String? = null,
    val retryable: Boolean = false,
    val action: String = ""
) {
    fun toOperationError(): OperationError =
        OperationError(
            code = code,
            stage = stage,
            message = message,
            traceId = traceId,
            requestId = requestId,
            retryable = retryable,
            action = action
        )
}

class ApiException(
    val apiError: ApiError,
    message: String? = apiError.message
) : Exception(message)
