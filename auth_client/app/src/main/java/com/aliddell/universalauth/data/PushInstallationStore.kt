package com.aliddell.universalauth.data

import android.content.Context
import android.content.SharedPreferences

/**
 * Caches the Firebase installation ID locally.
 *
 * Firebase can hand us an installation ID before the Pixel has been paired with
 * the broker, in which case the broker correctly rejects the registration. The
 * cached value lets the app retry once trust exists, and lets it avoid
 * re-sending an ID the broker already has.
 *
 * The installation ID is only a delivery address, never a credential.
 */
class PushInstallationStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("universal_auth_push", Context.MODE_PRIVATE)

    var installationId: String?
        get() = prefs.getString(KEY_INSTALLATION_ID, null)
        set(value) {
            prefs.edit().apply {
                if (value == null) remove(KEY_INSTALLATION_ID) else putString(KEY_INSTALLATION_ID, value)
            }.apply()
        }

    /** The installation ID the broker has already accepted, if any. */
    var registeredInstallationId: String?
        get() = prefs.getString(KEY_REGISTERED_ID, null)
        set(value) {
            prefs.edit().apply {
                if (value == null) remove(KEY_REGISTERED_ID) else putString(KEY_REGISTERED_ID, value)
            }.apply()
        }

    /** True when there is an installation ID the broker has not accepted yet. */
    fun needsRegistration(): Boolean {
        val current = installationId ?: return false
        return current != registeredInstallationId
    }

    private companion object {
        const val KEY_INSTALLATION_ID = "installation_id"
        const val KEY_REGISTERED_ID = "registered_installation_id"
    }
}
