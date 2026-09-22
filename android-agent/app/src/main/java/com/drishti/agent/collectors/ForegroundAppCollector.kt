package com.drishti.agent.collectors

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import com.drishti.agent.models.ForegroundAppTelemetry
import java.time.Instant

/**
 * Collects foreground application telemetry using UsageStatsManager.
 * Requires user-granted PACKAGE_USAGE_STATS permission via Settings.
 */
class ForegroundAppCollector(private val context: Context) {

    fun collect(): ForegroundAppTelemetry {
        if (!hasUsageStatsPermission()) {
            return ForegroundAppTelemetry(
                package_name = null,
                app_name = null,
                foreground_since = null,
                usage_duration_seconds = null,
                capability_status = "PERMISSION_REQUIRED"
            )
        }

        val usageStatsManager = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return ForegroundAppTelemetry(
                package_name = null,
                app_name = null,
                foreground_since = null,
                usage_duration_seconds = null,
                capability_status = "UNAVAILABLE"
            )

        val pm = context.packageManager
        val endTime = System.currentTimeMillis()
        val startTime = endTime - (1000 * 60 * 30) // past 30 minutes

        try {
            val events = usageStatsManager.queryEvents(startTime, endTime)
            var lastForegroundPkg: String? = null
            var lastForegroundTime = 0L

            val event = UsageEvents.Event()
            while (events.hasNextEvent()) {
                events.getNextEvent(event)
                if (event.eventType == UsageEvents.Event.ACTIVITY_RESUMED) {
                    if (event.packageName != context.packageName) {
                        lastForegroundPkg = event.packageName
                        lastForegroundTime = event.timeStamp
                    }
                }
            }

            if (lastForegroundPkg != null && lastForegroundTime > 0) {
                val appName = try {
                    val appInfo = pm.getApplicationInfo(lastForegroundPkg, 0)
                    pm.getApplicationLabel(appInfo).toString()
                } catch (_: Exception) {
                    lastForegroundPkg
                }

                val durationSeconds = (endTime - lastForegroundTime) / 1000

                return ForegroundAppTelemetry(
                    package_name = lastForegroundPkg,
                    app_name = appName,
                    foreground_since = Instant.ofEpochMilli(lastForegroundTime).toString(),
                    usage_duration_seconds = durationSeconds,
                    capability_status = "ACTIVE"
                )
            }
        } catch (_: Exception) {
            // Fallback to queryUsageStats
        }

        return ForegroundAppTelemetry(
            package_name = null,
            app_name = null,
            foreground_since = null,
            usage_duration_seconds = null,
            capability_status = "SUPPORTED_IDLE"
        )
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
