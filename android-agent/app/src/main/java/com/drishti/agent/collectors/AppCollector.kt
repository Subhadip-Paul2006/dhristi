package com.drishti.agent.collectors

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.drishti.agent.models.AppTelemetryItem
import com.drishti.agent.models.BrowserVisibility
import com.drishti.agent.models.SoftwareTelemetryItem
import java.security.MessageDigest
import java.time.Instant

class AppCollector(private val context: Context) {

    companion object {
        /** Well-known browser package names */
        private val BROWSER_PACKAGES = setOf(
            "com.android.chrome",
            "com.chrome.beta",
            "com.chrome.dev",
            "com.chrome.canary",
            "org.mozilla.firefox",
            "org.mozilla.fenix",
            "com.brave.browser",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.microsoft.emmx",
            "com.vivaldi.browser",
            "com.duckduckgo.mobile.android",
            "com.sec.android.app.sbrowser",
            "com.UCMobile.intl",
            "org.chromium.chrome"
        )
    }

    fun collect(): Pair<List<AppTelemetryItem>, List<SoftwareTelemetryItem>> {
        val pm = context.packageManager
        val appTelemetryList = mutableListOf<AppTelemetryItem>()
        val softwareTelemetryList = mutableListOf<SoftwareTelemetryItem>()

        val packages: List<PackageInfo> = getInstalledPackages(pm)

        val nowIso = Instant.now().toString()

        for (pkg in packages) {
            val appInfo = pkg.applicationInfo ?: continue
            val packageName = pkg.packageName ?: continue
            val label = try {
                appInfo.loadLabel(pm).toString()
            } catch (_: Exception) {
                packageName
            }
            val versionName = pkg.versionName
            val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkg.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                pkg.versionCode.toLong()
            }

            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val classification = if (isSystem) "SYSTEM_APP" else "USER_APP"
            val isEnabled = appInfo.enabled

            // Install and update timestamps
            val firstInstallTime = try {
                Instant.ofEpochMilli(pkg.firstInstallTime).toString()
            } catch (_: Exception) { null }

            val lastUpdateTime = try {
                Instant.ofEpochMilli(pkg.lastUpdateTime).toString()
            } catch (_: Exception) { null }

            // Requested permissions (limited to declared, not runtime state)
            val requestedPermissions = try {
                getPackagePermissions(pm, packageName)
            } catch (_: Exception) { null }

            // Signing certificate SHA-256
            val signingSha256 = try {
                getSigningCertSha256(pm, packageName)
            } catch (_: Exception) { null }

            appTelemetryList.add(
                AppTelemetryItem(
                    package_name = packageName,
                    label = label,
                    version_name = versionName,
                    version_code = versionCode,
                    classification = classification,
                    is_enabled = isEnabled,
                    first_install_time = firstInstallTime,
                    last_update_time = lastUpdateTime,
                    requested_permissions = requestedPermissions,
                    signing_sha256 = signingSha256
                )
            )

            softwareTelemetryList.add(
                SoftwareTelemetryItem(
                    name = label.ifBlank { packageName },
                    version = versionName,
                    vendor = classification,
                    install_date = firstInstallTime,
                    source = "android_package",
                    observed_at = nowIso
                )
            )
        }

        return Pair(appTelemetryList, softwareTelemetryList)
    }

    /**
     * Detects installed browsers and builds BrowserVisibility telemetry.
     */
    fun collectBrowserVisibility(foregroundPackage: String? = null): BrowserVisibility {
        val pm = context.packageManager
        val packages = getInstalledPackages(pm)
        val installedBrowsers = mutableListOf<String>()
        var chromeDetected = false

        for (pkg in packages) {
            val packageName = pkg.packageName ?: continue
            if (BROWSER_PACKAGES.contains(packageName)) {
                val label = try {
                    pkg.applicationInfo?.loadLabel(pm)?.toString() ?: packageName
                } catch (_: Exception) { packageName }
                installedBrowsers.add(label)
                if (packageName.startsWith("com.android.chrome") || packageName.startsWith("com.chrome.")) {
                    chromeDetected = true
                }
            }
        }

        val foregroundBrowser = if (foregroundPackage != null && BROWSER_PACKAGES.contains(foregroundPackage)) {
            foregroundPackage
        } else null

        val foregroundState = when {
            foregroundBrowser != null -> "FOREGROUND"
            chromeDetected -> "BACKGROUND_OR_INACTIVE"
            else -> null
        }

        return BrowserVisibility(
            installed_browsers = installedBrowsers,
            chrome_detected = chromeDetected,
            foreground_browser = foregroundBrowser,
            foreground_state = foregroundState,
            tab_visibility_capability = "PLATFORM_RESTRICTED",
            history_capability = "PLATFORM_RESTRICTED",
            note = "Android sandboxing prevents cross-app browser tab/history access"
        )
    }

    private fun getInstalledPackages(pm: PackageManager): List<PackageInfo> {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun getPackagePermissions(pm: PackageManager, packageName: String): List<String>? {
        return try {
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }
            info.requestedPermissions?.toList()
        } catch (_: Exception) {
            null
        }
    }

    @Suppress("DEPRECATION")
    private fun getSigningCertSha256(pm: PackageManager, packageName: String): String? {
        return try {
            val signingInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val si = info.signingInfo
                if (si != null && si.hasMultipleSigners()) {
                    si.apkContentsSigners?.firstOrNull()
                } else {
                    si?.signingCertificateHistory?.firstOrNull()
                }
            } else {
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                info.signatures?.firstOrNull()
            }

            if (signingInfo != null) {
                val md = MessageDigest.getInstance("SHA-256")
                val digest = md.digest(signingInfo.toByteArray())
                digest.joinToString(":") { "%02X".format(it) }
            } else null
        } catch (_: Exception) {
            null
        }
    }
}
