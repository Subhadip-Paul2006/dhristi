package com.drishti.agent.collectors

import android.app.AppOpsManager
import android.app.usage.UsageStats
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.Process
import com.drishti.agent.models.ProcessTelemetryItem

class ProcessCollector(private val context: Context) {

    fun collect(): List<ProcessTelemetryItem> {
        val list = mutableListOf<ProcessTelemetryItem>()
        val nowIso = java.time.Instant.now().toString()

        // 1. Collect own application process information
        val ownPid = Process.myPid()
        val ownMemoryMb = getOwnMemoryMb()

        list.add(
            ProcessTelemetryItem(
                pid = ownPid,
                name = context.packageName,
                category = "USER_APPLICATION",
                cpu_percent = null, // SELinux blocks /proc/PID/stat for non-root
                memory_mb = ownMemoryMb,
                exe_path = context.applicationInfo.sourceDir,
                username = "u0_a" + (Process.myUid() % 100000),
                started_at = null,
                observed_at = nowIso
            )
        )

        // 2. If user explicitly granted PACKAGE_USAGE_STATS permission, query recent foreground apps
        if (hasUsageStatsPermission()) {
            val usageStatsManager = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            if (usageStatsManager != null) {
                val endTime = System.currentTimeMillis()
                val startTime = endTime - (1000 * 60 * 60) // past 1 hour

                val statsList: List<UsageStats> = try {
                    usageStatsManager.queryUsageStats(UsageStatsManager.INTERVAL_BEST, startTime, endTime)
                } catch (_: Exception) {
                    emptyList()
                }

                // Filter to apps with recent activity
                val activeRecent = statsList
                    .filter { it.lastTimeUsed > startTime && it.packageName != context.packageName }
                    .sortedByDescending { it.lastTimeUsed }
                    .take(20)

                for (stat in activeRecent) {
                    list.add(
                        ProcessTelemetryItem(
                            pid = 0, // PIDs of other apps are not exposed by UsageStatsManager in Android 14+
                            name = stat.packageName,
                            category = "USER_APPLICATION",
                            cpu_percent = null,
                            memory_mb = null,
                            exe_path = null,
                            username = null,
                            started_at = java.time.Instant.ofEpochMilli(stat.firstTimeStamp).toString(),
                            observed_at = java.time.Instant.ofEpochMilli(stat.lastTimeUsed).toString()
                        )
                    )
                }
            }
        }

        return list
    }

    private fun getOwnMemoryMb(): Double? {
        return try {
            val memInfo = Debug.MemoryInfo()
            Debug.getMemoryInfo(memInfo)
            val totalKb = memInfo.totalPss
            if (totalKb > 0) {
                totalKb.toDouble() / 1024.0
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    fun hasUsageStatsPermission(): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }
}
