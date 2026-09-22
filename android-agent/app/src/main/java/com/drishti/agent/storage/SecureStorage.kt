package com.drishti.agent.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.drishti.agent.models.EndpointIdentity
import java.util.UUID

class SecureStorage(private val context: Context) {

    private val masterKey: MasterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private val prefs: SharedPreferences by lazy {
        try {
            EncryptedSharedPreferences.create(
                context,
                "drishti_secure_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            // Fallback for environments where Keystore AES256_SIV is unavailable (e.g. unit tests / older emulators)
            context.getSharedPreferences("drishti_fallback_prefs", Context.MODE_PRIVATE)
        }
    }

    companion object {
        private const val KEY_AGENT_ID = "agent_id"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_AGENT_TOKEN = "agent_token"
        private const val KEY_ORG_ID = "org_id"
        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_DEMO_MODE = "demo_mode"
        private const val DEFAULT_SERVER_URL = "http://10.0.2.2:8000" // Android emulator loopback to host
    }

    fun getOrCreateIdentity(
        hostname: String,
        osVersion: String,
        manufacturer: String,
        model: String,
        sdkVersion: Int,
        agentVersion: String = "0.1.0",
        currentIp: String? = null
    ): EndpointIdentity {
        var agentId = prefs.getString(KEY_AGENT_ID, null)
        var deviceId = prefs.getString(KEY_DEVICE_ID, null)

        if (agentId == null || deviceId == null) {
            agentId = UUID.randomUUID().toString()
            deviceId = UUID.randomUUID().toString()
            prefs.edit()
                .putString(KEY_AGENT_ID, agentId)
                .putString(KEY_DEVICE_ID, deviceId)
                .apply()
        }

        val nowIso = java.time.Instant.now().toString()

        return EndpointIdentity(
            agent_id = agentId,
            device_id = deviceId,
            hostname = hostname,
            os = "android",
            os_version = osVersion,
            mac = null, // MAC is strictly prohibited/randomized on Android 11+
            current_ip = currentIp,
            agent_version = agentVersion,
            manufacturer = manufacturer,
            model = model,
            sdk_version = sdkVersion,
            created_at = nowIso
        )
    }

    fun getAgentId(): String? = prefs.getString(KEY_AGENT_ID, null)

    fun getDeviceId(): String? = prefs.getString(KEY_DEVICE_ID, null)

    fun getAuthToken(): String? = prefs.getString(KEY_AGENT_TOKEN, null)

    fun getOrgId(): String? = prefs.getString(KEY_ORG_ID, null)

    fun saveAuth(token: String, orgId: String?) {
        prefs.edit()
            .putString(KEY_AGENT_TOKEN, token)
            .putString(KEY_ORG_ID, orgId)
            .apply()
    }

    fun isPaired(): Boolean = getAuthToken() != null

    fun getServerUrl(): String = prefs.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL) ?: DEFAULT_SERVER_URL

    fun setServerUrl(url: String) {
        val cleanUrl = url.trimEnd('/')
        prefs.edit().putString(KEY_SERVER_URL, cleanUrl).apply()
    }

    fun forceRePair() {
        prefs.edit()
            .remove(KEY_AGENT_TOKEN)
            .remove(KEY_ORG_ID)
            .apply()
    }

    fun isDemoMode(): Boolean {
        return prefs.getBoolean(KEY_DEMO_MODE, true) // Default true for hackathon demo build
    }

    fun setDemoMode(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_DEMO_MODE, enabled).apply()
    }

    fun clearAll() {
        prefs.edit().clear().apply()
    }
}
