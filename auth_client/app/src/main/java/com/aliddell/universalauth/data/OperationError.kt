package com.aliddell.universalauth.data

data class OperationError(
    val code: String,
    val stage: String,
    val message: String,
    val traceId: String?,
    val requestId: String?,
    val retryable: Boolean,
    val action: String
)
