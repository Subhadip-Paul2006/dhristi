package com.drishti.agent.collectors

import android.os.Build
import android.os.PowerManager
import android.content.Context
import com.drishti.agent.models.CpuTelemetry
import java.io.File
import java.io.RandomAccessFile

class CpuCollector(private val context: Context? = null) {

    fun collect(): CpuTelemetry {
        val cores = Runtime.getRuntime().availableProcessors()
        val architecture = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"

        // CPU usage from /proc/stat — blocked by SELinux on API 26+ for third-party apps
        var usagePercent: Double? = null
        var perCoreSupported = false
        val perCoreUsage = mutableListOf<Double>()

        try {
            RandomAccessFile("/proc/stat", "r").use { reader ->
                val line = reader.readLine()
                if (!line.isNullOrBlank() && line.startsWith("cpu ")) {
                    val tokens = line.split("\\s+".toRegex()).filter { it.isNotBlank() }
                    if (tokens.size >= 5) {
                        val user = tokens[1].toLongOrNull() ?: 0L
                        val nice = tokens[2].toLongOrNull() ?: 0L
                        val system = tokens[3].toLongOrNull() ?: 0L
                        val idle = tokens[4].toLongOrNull() ?: 0L
                        val total = user + nice + system + idle
                        val active = user + nice + system
                        if (total > 0) {
                            usagePercent = (active.toDouble() / total.toDouble()) * 100.0
                            perCoreSupported = true
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // SELinux blocks /proc/stat access — return honest unsupported states
            usagePercent = null
            perCoreSupported = false
        }

        // CPU frequency from sysfs (available on most Android devices even without root)
        val currentFreqMhz = readCpuFrequency("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
        val maxFreqMhz = readCpuFrequency("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
        val minFreqMhz = readCpuFrequency("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq")

        // Thermal status (API 29+)
        val (thermalStatus, isThrottled) = collectThermalStatus()

        return CpuTelemetry(
            cores = cores,
            usage_percent = usagePercent,
            per_core_supported = perCoreSupported,
            per_core_usage = perCoreUsage,
            architecture = architecture,
            cpu_frequency_mhz = currentFreqMhz,
            max_frequency_mhz = maxFreqMhz,
            min_frequency_mhz = minFreqMhz,
            thermal_status = thermalStatus,
            is_throttled = isThrottled
        )
    }

    /**
     * Reads CPU frequency from sysfs. Values are in kHz in the file,
     * returned in MHz for readability. Returns null if inaccessible.
     */
    private fun readCpuFrequency(path: String): Long? {
        return try {
            val file = File(path)
            if (file.exists() && file.canRead()) {
                val kHz = file.readText().trim().toLongOrNull()
                if (kHz != null && kHz > 0) kHz / 1000 else null
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Reads thermal status from PowerManager (API 29+).
     * Returns (statusString, isThrottled).
     */
    private fun collectThermalStatus(): Pair<String?, Boolean?> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || context == null) {
            return Pair(null, null)
        }

        return try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            if (pm != null) {
                val status = pm.currentThermalStatus
                val statusStr = when (status) {
                    PowerManager.THERMAL_STATUS_NONE -> "NONE"
                    PowerManager.THERMAL_STATUS_LIGHT -> "LIGHT"
                    PowerManager.THERMAL_STATUS_MODERATE -> "MODERATE"
                    PowerManager.THERMAL_STATUS_SEVERE -> "SEVERE"
                    PowerManager.THERMAL_STATUS_CRITICAL -> "CRITICAL"
                    PowerManager.THERMAL_STATUS_EMERGENCY -> "EMERGENCY"
                    PowerManager.THERMAL_STATUS_SHUTDOWN -> "SHUTDOWN"
                    else -> "UNKNOWN"
                }
                val throttled = status >= PowerManager.THERMAL_STATUS_MODERATE
                Pair(statusStr, throttled)
            } else {
                Pair(null, null)
            }
        } catch (_: Exception) {
            Pair(null, null)
        }
    }
}
