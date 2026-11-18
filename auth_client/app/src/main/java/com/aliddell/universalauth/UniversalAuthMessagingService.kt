package com.aliddell.universalauth

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
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
private const val CHANNEL_ID = "credential_requests"
private const val NOTIFICATION_ID = 42

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
        // Cache the ID so a deferred registration can be retried after pairing,
        // but always attempt the upload. Firebase recommends sending the FID to
        // the server on every callback, and the broker -- not this local cache --
        // must stay authoritative about whether the FID is registered. The
        // installation ID itself is never logged.
        pushStore.installationId = installationId
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
        showRequestNotification(requestId)
    }

    private fun showRequestNotification(requestId: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            nm.getNotificationChannel(CHANNEL_ID) == null
        ) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "Credential requests",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Alerts when a credential release needs approval"
                }
            )
        }
        val launch = PendingIntent.getActivity(
            this, 0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(applicationInfo.icon)
            .setContentTitle("Universal Auth")
            .setContentText("A request needs your approval")
            .setContentIntent(launch)
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_REMINDER)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .build()
        nm.notify(NOTIFICATION_ID, notification)
    }
}
