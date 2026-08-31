package com.aliddell.universalauth

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.aliddell.universalauth.crypto.SecureRelease
import com.aliddell.universalauth.crypto.VaultKeyManager
import com.aliddell.universalauth.data.ApiError
import com.aliddell.universalauth.data.ApiException
import com.aliddell.universalauth.data.AuthRepository
import com.aliddell.universalauth.data.AuthRequest
import com.aliddell.universalauth.data.DeviceRegistrationWithVault
import com.aliddell.universalauth.data.OperationError
import com.aliddell.universalauth.data.ReleaseRequest
import com.aliddell.universalauth.data.ReleaseResponse
import com.aliddell.universalauth.data.ReleaseStage
import com.aliddell.universalauth.data.TrustedDesktop
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Base64

class AuthViewModel(private val repository: AuthRepository) : ViewModel() {
    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState

    init {
        refresh()
        loadTrustedDesktop()
    }

    fun loadTrustedDesktop() {
        viewModelScope.launch {
            val result = repository.getTrustedDesktop()
            _uiState.value = _uiState.value.copy(
                trustedDesktop = result.getOrNull(),
                error = result.exceptionOrNull()?.message ?: _uiState.value.error
            )
        }
    }

    fun refresh() {
        _uiState.value = _uiState.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val health = repository.checkHealth()
            if (health.isFailure) {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    status = "unreachable",
                    error = health.exceptionOrNull()?.message
                )
                return@launch
            }
            val result = repository.getPendingRequests()
            _uiState.value = _uiState.value.copy(
                loading = false,
                status = "connected",
                requests = result.getOrDefault(emptyList()),
                error = result.exceptionOrNull()?.message
            )
        }
    }

    fun registerDevice(
        deviceId: String,
        name: String,
        algorithm: String,
        publicKey: String,
        vaultKeyId: String,
        vaultAlgorithm: String,
        vaultPublicKey: String
    ) {
        _uiState.value = _uiState.value.copy(loading = true, error = null)
        viewModelScope.launch {
            val registration = DeviceRegistrationWithVault(
                deviceId, name, algorithm, publicKey,
                vaultKeyId, vaultAlgorithm, vaultPublicKey
            )
            val result = repository.registerDevice(registration)
            if (result.isSuccess) {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    deviceRegistered = true,
                    error = null
                )
            } else {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    deviceRegistered = false,
                    error = result.exceptionOrNull()?.message
                )
            }
        }
    }

    fun decide(id: String, approved: Boolean) {
        if (!approved) {
            submitDenial(id)
        }
    }

    private fun submitDenial(id: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, error = null)
            val result = repository.submitDenial(id)
            if (result.isSuccess) {
                refresh()
            } else {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    error = result.exceptionOrNull()?.message
                )
            }
        }
    }

    fun submitSignedApproval(id: String, deviceId: String, signature: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, error = null)
            val result = repository.submitSignedApproval(id, deviceId, signature)
            if (result.isSuccess) {
                refresh()
            } else {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    error = result.exceptionOrNull()?.message
                )
            }
        }
    }

    fun setReleaseStage(stage: ReleaseStage) {
        _uiState.value = _uiState.value.copy(releaseStage = stage)
    }

    fun submitReleaseResponse(id: String, response: ReleaseResponse) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(loading = true, error = null)
            val result = repository.submitReleaseResponse(id, response)
            if (result.isSuccess) {
                refresh()
            } else {
                _uiState.value = _uiState.value.copy(
                    loading = false,
                    error = result.exceptionOrNull()?.message
                )
            }
        }
    }

    fun performRelease(
        request: AuthRequest,
        release: ReleaseRequest,
        onResult: (String) -> Unit
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                loading = true,
                error = null,
                releaseStage = ReleaseStage.VALIDATING_REQUEST,
                releaseError = null
            )
            val trusted = _uiState.value.trustedDesktop
            if (trusted == null) {
                val err = operationError(request, "UA-BROKER-002", "broker.trusted_desktop", "No trusted desktop registered", "Run 'authctl desktop-register'.", false)
                _uiState.value = _uiState.value.copy(loading = false, releaseStage = ReleaseStage.FAILED, releaseError = err)
                onResult(err.message)
                return@launch
            }
            try {
                val response = withContext(Dispatchers.IO) {
                    val desktopPublic = Base64.getDecoder().decode(trusted.public_key)
                    val vaultKeyManager = VaultKeyManager()
                    SecureRelease.process(
                        requestId = request.id,
                        challenge = request.challenge,
                        clientNonce = request.clientNonce,
                        release = release,
                        pinnedDesktopId = trusted.desktop_id,
                        pinnedDesktopPublic = desktopPublic,
                        pinnedPixelVaultKeyId = vaultKeyManager.keyId(),
                        vaultKeyManager = vaultKeyManager,
                        onStage = { stage ->
                            _uiState.value = _uiState.value.copy(releaseStage = stage)
                        }
                    )
                }
                _uiState.value = _uiState.value.copy(releaseStage = ReleaseStage.SENDING_RESPONSE)
                val result = repository.submitReleaseResponse(request.id, response)
                if (result.isSuccess) {
                    _uiState.value = _uiState.value.copy(loading = false, releaseStage = ReleaseStage.COMPLETE, releaseError = null)
                    onResult("")
                    refresh()
                } else {
                    val ex = result.exceptionOrNull()
                    val err = toOperationError(ex, request, "broker.attach_release_response")
                    _uiState.value = _uiState.value.copy(loading = false, releaseStage = ReleaseStage.FAILED, releaseError = err)
                    onResult(err.message)
                }
            } catch (e: ApiException) {
                val err = toOperationError(e, request, e.apiError.stage)
                _uiState.value = _uiState.value.copy(loading = false, releaseStage = ReleaseStage.FAILED, releaseError = err)
                onResult(err.message)
            } catch (e: Exception) {
                val code = if (e is java.lang.SecurityException) "UA-ANDROID-010" else "UA-ANDROID-001"
                val err = operationError(request, code, "release.process", e.message ?: e.javaClass.simpleName, "Check the request and try again.", false)
                _uiState.value = _uiState.value.copy(loading = false, releaseStage = ReleaseStage.FAILED, releaseError = err)
                onResult(err.message)
            }
        }
    }

    private fun toOperationError(throwable: Throwable?, request: AuthRequest, fallbackStage: String): OperationError {
        return when (throwable) {
            is ApiException -> operationError(
                request = request,
                code = throwable.apiError.code,
                stage = throwable.apiError.stage.ifEmpty { fallbackStage },
                message = throwable.apiError.message,
                action = throwable.apiError.action,
                retryable = throwable.apiError.retryable
            )
            else -> operationError(
                request = request,
                code = "UA-ANDROID-001",
                stage = fallbackStage,
                message = throwable?.message ?: "Release failed",
                action = "Check the request and try again.",
                retryable = false
            )
        }
    }

    private fun operationError(
        request: AuthRequest,
        code: String,
        stage: String,
        message: String,
        action: String,
        retryable: Boolean
    ): OperationError {
        return OperationError(
            code = code,
            stage = stage,
            message = message,
            traceId = request.traceId,
            requestId = request.id,
            retryable = retryable,
            action = action
        )
    }

    data class UiState(
        val loading: Boolean = true,
        val status: String = "unknown",
        val deviceRegistered: Boolean = false,
        val requests: List<AuthRequest> = emptyList(),
        val trustedDesktop: TrustedDesktop? = null,
        val error: String? = null,
        val releaseStage: ReleaseStage = ReleaseStage.IDLE,
        val releaseError: OperationError? = null
    )

    class Factory(private val repository: AuthRepository) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(AuthViewModel::class.java)) {
                return AuthViewModel(repository) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}
