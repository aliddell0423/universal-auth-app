@file:OptIn(ExperimentalMaterial3Api::class)
package com.aliddell.universalauth

import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.aliddell.universalauth.crypto.ApprovalKeyManager
import com.aliddell.universalauth.crypto.KeyManagerException
import com.aliddell.universalauth.crypto.VaultKeyManager
import com.aliddell.universalauth.crypto.buildSigningPayload
import com.aliddell.universalauth.data.AuthRequest
import com.aliddell.universalauth.data.DefaultAuthRepository
import java.security.Signature
import java.util.Base64

class MainActivity : FragmentActivity() {

    private val authViewModel: AuthViewModel by viewModels {
        AuthViewModel.Factory(DefaultAuthRepository())
    }

    private val keyManager = ApprovalKeyManager()
    private val vaultKeyManager = VaultKeyManager()
    private var pendingBiometricRequest: AuthRequest? = null
    private lateinit var biometricPrompt: BiometricPrompt

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val request = pendingBiometricRequest
                    if (request != null) {
                        try {
                            if (request.kind == "credential_release") {
                                val release = request.releaseRequest
                                    ?: throw KeyManagerException("No release request attached")
                                authViewModel.performRelease(request, release) { error ->
                                    if (error.isNotEmpty()) {
                                        Toast.makeText(
                                            this@MainActivity,
                                            "Secure release failed: $error",
                                            Toast.LENGTH_LONG
                                        ).show()
                                    }
                                }
                            } else {
                                val signature = result.cryptoObject?.signature
                                    ?: throw KeyManagerException("Biometric result did not contain a signature")
                                val payload = buildSigningPayload(request, "approved")
                                signature.update(payload)
                                val signed = signature.sign()
                                val sigBase64 = Base64.getEncoder().encodeToString(signed)
                                authViewModel.submitSignedApproval(
                                    request.id,
                                    keyManager.deviceId(),
                                    sigBase64
                                )
                            }
                        } catch (e: Exception) {
                            Toast.makeText(
                                this@MainActivity,
                                "Signing failed: ${e.message}",
                                Toast.LENGTH_LONG
                            ).show()
                        } finally {
                            pendingBiometricRequest = null
                        }
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // Do not clear the pending request; the system prompt may continue.
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    pendingBiometricRequest = null
                    if (errorCode != BiometricPrompt.ERROR_USER_CANCELED &&
                        errorCode != BiometricPrompt.ERROR_CANCELED
                    ) {
                        Toast.makeText(
                            this@MainActivity,
                            "Biometric error: $errString",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }
            })

        try {
            keyManager.ensureKey()
            val (vaultKeyId, vaultPublic) = if (vaultKeyManager.isSupported()) {
                val pair = vaultKeyManager.ensureKey()
                vaultKeyManager.keyId() to vaultKeyManager.publicKeyEncoded()
            } else {
                "" to ""
            }
            authViewModel.registerDevice(
                keyManager.deviceId(),
                "Pixel 10",
                "ECDSA_P256_SHA256",
                keyManager.publicKeyEncoded(),
                vaultKeyId,
                if (vaultKeyManager.isSupported()) "ECDH_P256_HKDF_SHA256" else "",
                vaultPublic
            )
        } catch (e: KeyManagerException) {
            Toast.makeText(
                this,
                e.message ?: "Approval key is not available",
                Toast.LENGTH_LONG
            ).show()
        }

        setContent {
            val state = authViewModel.uiState.collectAsState()
            PendingRequestsScreen(
                state = state.value,
                onRefresh = { authViewModel.refresh() },
                onApprove = { request -> onApprove(request) },
                onDeny = { request -> authViewModel.decide(request.id, false) }
            )
        }
    }

    private fun onApprove(request: AuthRequest) {
        if (pendingBiometricRequest != null) return

        if (!authViewModel.uiState.value.deviceRegistered) {
            Toast.makeText(this, "Device is not registered for signed approval", Toast.LENGTH_LONG).show()
            return
        }

        val canAuth = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            val message = when (canAuth) {
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                    "No strong biometric hardware is available."
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                    "Strong biometric hardware is temporarily unavailable."
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                    "No strong biometric is enrolled on this device."
                else ->
                    "Strong biometric authentication is not available."
            }
            Toast.makeText(this, message, Toast.LENGTH_LONG).show()
            return
        }

        if (request.kind == "credential_release") {
            if (request.releaseRequest == null) {
                Toast.makeText(this, "No secure release data", Toast.LENGTH_LONG).show()
                return
            }
            if (authViewModel.uiState.value.trustedDesktop == null) {
                Toast.makeText(this, "No trusted desktop registered", Toast.LENGTH_LONG).show()
                return
            }
            pendingBiometricRequest = request
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Release credential")
                .setSubtitle("${request.source} / ${request.resource}")
                .setDescription("Authenticate to release this saved login")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .setNegativeButtonText("Cancel")
                .build()
            biometricPrompt.authenticate(promptInfo)
        } else {
            try {
                val signature = keyManager.createSignature()
                pendingBiometricRequest = request
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Approve authentication request")
                    .setSubtitle("${request.source} / ${request.resource}")
                    .setDescription("Authenticate to approve this request")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setConfirmationRequired(true)
                    .setNegativeButtonText("Cancel")
                    .build()
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
            } catch (e: KeyManagerException) {
                pendingBiometricRequest = null
                Toast.makeText(
                    this,
                    e.message ?: "Approval key is not available",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }
}

@Composable
fun PendingRequestsScreen(
    state: AuthViewModel.UiState,
    onRefresh: () -> Unit,
    onApprove: (AuthRequest) -> Unit,
    onDeny: (AuthRequest) -> Unit
) {
    Scaffold(
        topBar = { TopAppBar(title = { Text("Universal Auth") }) }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
        ) {
            Text("Broker: 192.168.1.167")
            Text("Status: ${state.status}")
            if (!state.deviceRegistered) {
                Text("Device not registered", color = MaterialTheme.colorScheme.error)
            }
            Spacer(modifier = Modifier.height(8.dp))
            Button(onClick = onRefresh) { Text("Refresh") }
            Spacer(modifier = Modifier.height(8.dp))
            state.error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
            if (state.loading) CircularProgressIndicator()
            if (!state.loading && state.requests.isEmpty()) Text("No pending requests")
            LazyColumn(contentPadding = PaddingValues(vertical = 8.dp)) {
                items(state.requests) { request ->
                    RequestCard(
                        request = request,
                        onApprove = { onApprove(request) },
                        onDeny = { onDeny(request) },
                        approveEnabled = state.deviceRegistered
                    )
                }
            }
        }
    }
}

@Composable
fun RequestCard(
    request: AuthRequest,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
    approveEnabled: Boolean
) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(request.source, style = MaterialTheme.typography.titleMedium)
            Text("${request.kind} - ${request.resource}")
            Text(request.message)
            Text("Created: ${request.createdAt}")
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Button(onClick = onDeny) { Text("Deny") }
                Button(onClick = onApprove, enabled = approveEnabled) { Text("Approve") }
            }
        }
    }
}
