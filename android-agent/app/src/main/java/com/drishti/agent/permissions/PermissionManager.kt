package com.drishti.agent.permissions

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Process
import android.provider.Settings
import androidx.core.content.ContextCompat

/**
 * Manages runtime and special permissions for the Drishti Android Agent.
 * Follows progressive disclosure and least-privilege principles.
 */
object PermissionManager {

    /**
     * Checks whether POST_NOTIFICATIONS is granted (Android 13+ / API 33+).
     */
    fun hasNotificationPermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    /**
     * Checks whether PACKAGE_USAGE_STATS is granted in AppOps.
     * This is a special permission required for detailed foreground application telemetry.
     */
    fun hasUsageStatsPermission(context: Context): Boolean {
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

    /**
     * Launches the system Settings screen allowing the user to grant usage stats access.
     */
    fun createUsageStatsSettingsIntent(): Intent {
        return Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
    }

    /**
     * Returns an intent for preparing the defensive VPN service, or null if already prepared.
     */
    fun prepareVpnIntent(context: Context): Intent? {
        return VpnService.prepare(context)
    }

    /**
     * Evaluates permission status overview for diagnostics.
     */
    data class PermissionOverview(
        val notificationsGranted: Boolean,
        val usageStatsGranted: Boolean,
        val vpnPrepared: Boolean,
        val internetGranted: Boolean
    )

    fun getOverview(context: Context): PermissionOverview {
        val notifications = hasNotificationPermission(context)
        val usageStats = hasUsageStatsPermission(context)
        val vpnPrepared = VpnService.prepare(context) == null
        val internet = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.INTERNET
        ) == PackageManager.PERMISSION_GRANTED

        return PermissionOverview(
            notificationsGranted = notifications,
            usageStatsGranted = usageStats,
            vpnPrepared = vpnPrepared,
            internetGranted = internet
        )
    }
}
