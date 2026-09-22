package com.drishti.agent.collectors

import android.content.Context
import android.os.Build
import androidx.core.content.ContextCompat
import com.drishti.agent.models.CapabilityStatusItem
import com.drishti.agent.services.DrishtiVpnService

/**
 * CapabilityMatrixCollector produces an honest, transparent breakdown of what
 * telemetry is supported, restricted by Android OS sandboxing, or requires
 * specific user permissions on the device.
 */
class CapabilityMatrixCollector(private val context: Context) {

    private val foregroundAppCollector = ForegroundAppCollector(context)

    fun collect(): List<CapabilityStatusItem> {
        val list = mutableListOf<CapabilityStatusItem>()

        // 1. Hardware & OS Telemetry
        list.add(CapabilityStatusItem("CPU_CORE_COUNT", "SUPPORTED", "Runtime.availableProcessors()"))
        list.add(CapabilityStatusItem("CPU_USAGE_PERCENT", "PLATFORM_RESTRICTED", "SELinux restricts non-root /proc/stat reads on Android 8.0+"))
        list.add(CapabilityStatusItem("CPU_THERMAL_STATUS", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) "SUPPORTED" else "UNSUPPORTED_ON_API", "PowerManager.getCurrentThermalStatus()"))
        list.add(CapabilityStatusItem("CPU_FREQUENCY", "SUPPORTED", "sysfs scaling_cur_freq / cpuinfo_cur_freq"))

        list.add(CapabilityStatusItem("MEMORY_SYSTEM", "SUPPORTED", "ActivityManager.MemoryInfo"))
        list.add(CapabilityStatusItem("MEMORY_APP_PSS", "SUPPORTED", "Debug.getMemoryInfo(myPid)"))

        list.add(CapabilityStatusItem("STORAGE_INTERNAL", "SUPPORTED", "StatFs(Environment.getDataDirectory())"))
        list.add(CapabilityStatusItem("STORAGE_EXTERNAL", "SUPPORTED", "StatFs(Environment.getExternalStorageDirectory())"))

        list.add(CapabilityStatusItem("BATTERY_STATUS", "SUPPORTED", "BatteryManager intent broadcast"))
        list.add(CapabilityStatusItem("BATTERY_POWER_SAVE", "SUPPORTED", "PowerManager.isPowerSaveMode"))

        // 2. Network Telemetry
        list.add(CapabilityStatusItem("NETWORK_CONNECTIVITY", "SUPPORTED", "ConnectivityManager.getNetworkCapabilities"))
        list.add(CapabilityStatusItem("NETWORK_TRAFFIC_STATS", "SUPPORTED", "TrafficStats.getTotalRxBytes / getTotalTxBytes"))

        val hasLocation = ContextCompat.checkSelfPermission(
            context,
            android.Manifest.permission.ACCESS_FINE_LOCATION
        ) == android.content.pm.PackageManager.PERMISSION_GRANTED

        list.add(
            CapabilityStatusItem(
                "WIFI_SSID_BSSID",
                if (hasLocation) "SUPPORTED" else "PERMISSION_REQUIRED",
                if (hasLocation) "WifiManager / LinkProperties" else "Requires user-granted ACCESS_FINE_LOCATION on Android 10+"
            )
        )

        val vpnRunning = DrishtiVpnService.isRunning.get()
        list.add(
            CapabilityStatusItem(
                "DEFENSIVE_VPN_FLOWS",
                if (vpnRunning) "ACTIVE" else "REQUIRES_USER_CONSENT",
                if (vpnRunning) "DrishtiVpnService destination flow tracking" else "Requires user activation of Defensive Shield"
            )
        )

        // 3. Application Telemetry
        list.add(CapabilityStatusItem("INSTALLED_APPS_INVENTORY", "SUPPORTED", "PackageManager.getInstalledPackages"))
        list.add(CapabilityStatusItem("APP_PERMISSIONS_INVENTORY", "SUPPORTED", "PackageManager.GET_PERMISSIONS"))
        list.add(CapabilityStatusItem("APP_SIGNING_CERT_SHA256", "SUPPORTED", "PackageManager.GET_SIGNING_CERTIFICATES"))

        val hasUsageStats = foregroundAppCollector.hasUsageStatsPermission()
        list.add(
            CapabilityStatusItem(
                "FOREGROUND_APP_TRACKING",
                if (hasUsageStats) "ACTIVE" else "PERMISSION_REQUIRED",
                if (hasUsageStats) "UsageStatsManager queryEvents" else "Requires Settings > Usage Access permission"
            )
        )

        // 4. Security & Isolation Limits (Honest Reporting)
        list.add(
            CapabilityStatusItem(
                "PROCESS_LIST_GLOBAL",
                if (hasUsageStats) "PARTIAL" else "OWN_PROCESS_ONLY",
                if (hasUsageStats) "Recent active apps via UsageStatsManager; PIDs hidden by Android 14+ sandbox" else "Only own process accessible; requires Usage Access for recent app activity"
            )
        )

        list.add(
            CapabilityStatusItem(
                "BROWSER_TABS_HISTORY",
                "PLATFORM_RESTRICTED",
                "Android application sandboxing strictly forbids cross-app browser tab and history inspection without device management enrollment"
            )
        )

        list.add(
            CapabilityStatusItem(
                "SOCKET_INSPECTION_GLOBAL",
                "PLATFORM_RESTRICTED",
                "Android 10+ SELinux policy restricts /proc/net/tcp access to system UID"
            )
        )

        list.add(CapabilityStatusItem("SECURITY_POSTURE_ROOT", "SUPPORTED", "Multi-heuristic su/busybox/test-keys checks"))
        list.add(CapabilityStatusItem("SECURITY_POSTURE_ENCRYPTION", "SUPPORTED", "DevicePolicyManager / KeyguardManager"))

        return list
    }
}
