package com.drishti.agent.collectors

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import com.drishti.agent.models.DeviceInfoTelemetry
import com.drishti.agent.models.UptimeTelemetry
import java.io.File
import java.time.Instant
import java.util.Locale
import java.util.TimeZone

data class DeviceInfoResult(
    val manufacturer: String,
    val model: String,
    val androidVersion: String,
    val sdkVersion: Int,
    val architecture: String,
    val uptimeSeconds: Long,
    val deviceName: String,
    val agentVersion: String = "0.1.0",
    // Extended fields
    val buildDisplay: String? = null,
    val buildFingerprint: String? = null,
    val supportedAbis: List<String> = emptyList(),
    val kernelVersion: String? = null,
    val locale: String? = null,
    val timezone: String? = null,
    val isEmulator: Boolean = false,
    val bootTimestamp: String? = null
)

class DeviceInfoCollector(private val context: Context) {

    fun collect(): DeviceInfoResult {
        val manufacturer = Build.MANUFACTURER ?: "Unknown"
        val model = Build.MODEL ?: "Android Device"
        val androidVersion = Build.VERSION.RELEASE ?: "Unknown"
        val sdkVersion = Build.VERSION.SDK_INT
        val architecture = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        val uptimeSeconds = SystemClock.elapsedRealtime() / 1000

        var deviceName: String? = null
        try {
            deviceName = Settings.Global.getString(context.contentResolver, "device_name")
        } catch (_: Exception) {
        }

        if (deviceName.isNullOrBlank()) {
            try {
                deviceName = Settings.Secure.getString(context.contentResolver, "bluetooth_name")
            } catch (_: Exception) {
            }
        }

        if (deviceName.isNullOrBlank()) {
            deviceName = "$manufacturer $model"
        }

        // Build info
        val buildDisplay = Build.DISPLAY
        val buildFingerprint = Build.FINGERPRINT
        val supportedAbis = Build.SUPPORTED_ABIS?.toList() ?: emptyList()

        // Kernel version (safe read from System property)
        val kernelVersion = try {
            System.getProperty("os.version")
        } catch (_: Exception) {
            null
        }

        // Locale and timezone
        val locale = Locale.getDefault().toLanguageTag()
        val timezone = TimeZone.getDefault().id

        // Emulator detection (heuristic, no exploitation)
        val isEmulator = detectEmulator()

        // Boot timestamp derived from uptime
        val bootTimestamp = try {
            val bootMs = System.currentTimeMillis() - SystemClock.elapsedRealtime()
            Instant.ofEpochMilli(bootMs).toString()
        } catch (_: Exception) {
            null
        }

        return DeviceInfoResult(
            manufacturer = manufacturer,
            model = model,
            androidVersion = androidVersion,
            sdkVersion = sdkVersion,
            architecture = architecture,
            uptimeSeconds = uptimeSeconds,
            deviceName = deviceName,
            buildDisplay = buildDisplay,
            buildFingerprint = buildFingerprint,
            supportedAbis = supportedAbis,
            kernelVersion = kernelVersion,
            locale = locale,
            timezone = timezone,
            isEmulator = isEmulator,
            bootTimestamp = bootTimestamp
        )
    }

    /**
     * Collects structured device info telemetry for backend serialization.
     */
    fun collectTelemetry(): DeviceInfoTelemetry {
        val result = collect()
        return DeviceInfoTelemetry(
            manufacturer = result.manufacturer,
            model = result.model,
            device_name = result.deviceName,
            android_version = result.androidVersion,
            sdk_version = result.sdkVersion,
            build_display = result.buildDisplay,
            build_fingerprint = result.buildFingerprint,
            architecture = result.architecture,
            supported_abis = result.supportedAbis,
            kernel_version = result.kernelVersion,
            locale = result.locale,
            timezone = result.timezone,
            is_emulator = result.isEmulator
        )
    }

    /**
     * Collects uptime telemetry.
     */
    fun collectUptime(
        lastHeartbeat: Instant? = null,
        agentServiceRunning: Boolean = false,
        lastTelemetryUpload: Instant? = null,
        offlineDurationSeconds: Long? = null
    ): UptimeTelemetry {
        val uptimeSeconds = SystemClock.elapsedRealtime() / 1000
        val bootMs = System.currentTimeMillis() - SystemClock.elapsedRealtime()
        val bootTimestamp = try { Instant.ofEpochMilli(bootMs).toString() } catch (_: Exception) { null }

        return UptimeTelemetry(
            uptime_seconds = uptimeSeconds,
            boot_timestamp = bootTimestamp,
            last_heartbeat = lastHeartbeat?.toString(),
            agent_service_running = agentServiceRunning,
            last_telemetry_upload = lastTelemetryUpload?.toString(),
            offline_duration_seconds = offlineDurationSeconds
        )
    }

    /**
     * Lightweight emulator heuristics. Uses Build properties only.
     * Reports conservatively — classified as emulator only if
     * multiple clear indicators align. No root exploit checks.
     */
    private fun detectEmulator(): Boolean {
        val indicators = mutableListOf<Boolean>()

        indicators.add(Build.FINGERPRINT.contains("generic", ignoreCase = true))
        indicators.add(Build.MODEL.contains("google_sdk", ignoreCase = true) ||
                Build.MODEL.contains("Emulator", ignoreCase = true) ||
                Build.MODEL.contains("Android SDK", ignoreCase = true))
        indicators.add(Build.MANUFACTURER.contains("Genymotion", ignoreCase = true))
        indicators.add(Build.HARDWARE.contains("goldfish", ignoreCase = true) ||
                Build.HARDWARE.contains("ranchu", ignoreCase = true))
        indicators.add(Build.PRODUCT.contains("sdk", ignoreCase = true) ||
                Build.PRODUCT.contains("emulator", ignoreCase = true))
        indicators.add(Build.BRAND == "google" && Build.DEVICE?.startsWith("generic") == true)

        // Check for qemu driver files (existence check only, no read)
        try {
            indicators.add(File("/dev/qemu_pipe").exists() || File("/dev/goldfish_pipe").exists())
        } catch (_: Exception) {
            indicators.add(false)
        }

        // Require at least 2 positive indicators to classify as emulator
        return indicators.count { it } >= 2
    }
}
