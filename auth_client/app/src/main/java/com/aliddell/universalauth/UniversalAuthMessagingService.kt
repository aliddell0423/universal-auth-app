package com.aliddell.universalauth

import android.util.Log
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class UniversalAuthMessagingService : FirebaseMessagingService() {

    override fun onRegistered(installationId: String) {
        Log.d("UniversalAuthFCM", "FCM registered successfully")
        Log.d("UniversalAuthFCM", "Installation ID: $installationId")
    }

    override fun onMessageReceived(message: RemoteMessage) {
        Log.d("UniversalAuthFCM", "FCM message received")
        Log.d("UniversalAuthFCM", "Data: ${message.data}")
    }
}