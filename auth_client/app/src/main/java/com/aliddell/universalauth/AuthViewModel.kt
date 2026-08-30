package com.aliddell.universalauth

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.aliddell.universalauth.data.AuthRepository
import com.aliddell.universalauth.data.AuthRequest
import com.aliddell.universalauth.data.DeviceRegistrationWithVault
import com.aliddell.universalauth.data.ReleaseResponse
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class AuthViewModel(private val repository: AuthRepository) : ViewModel() {
    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState

    init {
        refresh()
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

    data class UiState(
        val loading: Boolean = true,
        val status: String = "unknown",
        val deviceRegistered: Boolean = false,
        val requests: List<AuthRequest> = emptyList(),
        val error: String? = null
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
