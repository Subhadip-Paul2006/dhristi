package com.drishti.agent.collectors

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import com.drishti.agent.models.MemoryTelemetry

class MemoryCollector(private val context: Context) {

    fun collect(): MemoryTelemetry {
        val actManager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val memInfo = ActivityManager.MemoryInfo()

        // Get own process PSS/private dirty for app memory reporting
        val (pssKb, privateDirtyKb) = getOwnProcessMemory()

        if (actManager != null) {
            actManager.getMemoryInfo(memInfo)
            val totalBytes = memInfo.totalMem
            val availableBytes = memInfo.availMem
            val usedBytes = (totalBytes - availableBytes).coerceAtLeast(0L)
            val lowMemory = memInfo.lowMemory
            val usagePercent = if (totalBytes > 0) {
                (usedBytes.toDouble() / totalBytes.toDouble()) * 100.0
            } else null

            return MemoryTelemetry(
                total_bytes = totalBytes,
                available_bytes = availableBytes,
                used_bytes = usedBytes,
                usage_percent = usagePercent,
                low_memory = lowMemory,
                threshold_bytes = memInfo.threshold,
                process_pss_kb = pssKb,
                process_private_dirty_kb = privateDirtyKb
            )
        }

        // Fallback to Runtime memory if ActivityManager is unavailable
        val runtime = Runtime.getRuntime()
        val total = runtime.totalMemory()
        val free = runtime.freeMemory()
        val used = (total - free).coerceAtLeast(0L)

        return MemoryTelemetry(
            total_bytes = total,
            available_bytes = free,
            used_bytes = used,
            usage_percent = if (total > 0) (used.toDouble() / total.toDouble()) * 100.0 else null,
            low_memory = false,
            process_pss_kb = pssKb,
            process_private_dirty_kb = privateDirtyKb
        )
    }

    /**
     * Returns (totalPssKb, privateDirtyKb) for the calling process via Debug API.
     */
    private fun getOwnProcessMemory(): Pair<Int?, Int?> {
        return try {
            val memInfo = Debug.MemoryInfo()
            Debug.getMemoryInfo(memInfo)
            val pss = memInfo.totalPss
            val privateDirty = memInfo.totalPrivateDirty
            Pair(
                if (pss > 0) pss else null,
                if (privateDirty > 0) privateDirty else null
            )
        } catch (_: Exception) {
            Pair(null, null)
        }
    }
}
