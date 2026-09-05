package com.aliddell.universalauth

import android.util.Log
import com.aliddell.universalauth.crypto.ApprovalKeyManager
import com.aliddell.universalauth.data.AuthRepository
import com.aliddell.universalauth.data.DefaultAuthRepository
import com.aliddell.universalauth.data.PushInstallationStore
import com.aliddell.universalauth.data.PushRegistration
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

private const val TAG = "UniversalAuthFCM"

class UniversalAuthMessagingService : FirebaseMessagingService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val repository: AuthRepository by lazy { DefaultAuthRepository() }
    private val keyManager by lazy { ApprovalKeyManager() }
    private val pushStore by lazy { PushInstallationStore(applicationContext) }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onRegistered(installationId: String) {
        // Cache first so the app can retry after the Pixel is paired. Never log
        // the installation ID itself.
        pushStore.installationId = installationId
        if (pushStore.registeredInstallationId == installationId) {
            return
        }
        scope.launch { registerWithBroker(installationId) }
    }

    private suspend fun registerWithBroker(installationId: String) {
        val deviceId = runCatching { keyManager.deviceId() }.getOrElse { e ->
            Log.w(TAG, "Cannot read the approval key yet; push registration deferred", e)
            return
        }
        val result = repository.registerPushInstallation(
            PushRegistration(device_id = deviceId, installation_id = installationId)
        )
        if (result.isSuccess) {
            pushStore.registeredInstallationId = installationId
            Log.d(TAG, "Push registration accepted by broker")
        } else {
            // A rejection here is expected before pairing; MainActivity retries.
            Log.w(TAG, "Push registration deferred: ${result.exceptionOrNull()?.message}")
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        // Firebase only tells us that a request exists. The payload is never
        // treated as the request itself; the broker remains the source of truth,
        // so the notification handler will fetch request_id from the broker.
        val requestId = message.data["request_id"]
        val type = message.data["type"]
        if (type != "credential_request" || requestId.isNullOrEmpty()) {
            Log.w(TAG, "Ignoring push with unexpected type=$type")
            return
        }
        Log.d(TAG, "Credential request notification for request=$requestId")
    }
}
