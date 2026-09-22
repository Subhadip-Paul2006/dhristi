package com.drishti.agent.collectors

import android.os.Environment
import android.os.StatFs
import com.drishti.agent.models.StorageTelemetry

class StorageCollector {

    fun collect(): StorageTelemetry {
        val internal = collectInternalStorage()
        val external = collectExternalStorage()

        return StorageTelemetry(
            total_bytes = internal.first,
            available_bytes = internal.second,
            used_bytes = internal.third,
            usage_percent = if (internal.first > 0) {
                (internal.third.toDouble() / internal.first.toDouble()) * 100.0
            } else null,
            external_total_bytes = external?.first,
            external_available_bytes = external?.second,
            external_used_bytes = external?.third
        )
    }

    private fun collectInternalStorage(): Triple<Long, Long, Long> {
        return try {
            val path = Environment.getDataDirectory()
            val stat = StatFs(path.path)
            val totalBytes = stat.totalBytes
            val availableBytes = stat.availableBytes
            val usedBytes = (totalBytes - availableBytes).coerceAtLeast(0L)
            Triple(totalBytes, availableBytes, usedBytes)
        } catch (_: Exception) {
            Triple(0L, 0L, 0L)
        }
    }

    private fun collectExternalStorage(): Triple<Long, Long, Long>? {
        return try {
            val state = Environment.getExternalStorageState()
            if (state != Environment.MEDIA_MOUNTED && state != Environment.MEDIA_MOUNTED_READ_ONLY) {
                return null
            }

            val externalDir = Environment.getExternalStorageDirectory()
            val stat = StatFs(externalDir.path)
            val totalBytes = stat.totalBytes
            val availableBytes = stat.availableBytes
            val usedBytes = (totalBytes - availableBytes).coerceAtLeast(0L)
            Triple(totalBytes, availableBytes, usedBytes)
        } catch (_: Exception) {
            null
        }
    }
}
