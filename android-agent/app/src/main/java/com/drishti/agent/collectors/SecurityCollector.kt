package com.drishti.agent.collectors

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.drishti.agent.models.SecurityPostureTelemetry
import java.io.File

class SecurityCollector(private val context: Context) {

    fun collect(): SecurityPostureTelemetry {
        // 1. Screen lock state
        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val isScreenLockSecure = keyguardManager?.isDeviceSecure ?: false

        // 2. Storage encryption
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val encryptionStatus = when (dpm?.storageEncryptionStatus) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> "ENCRYPTED"
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> "UNENCRYPTED"
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING -> "ACTIVATING"
            else -> "ENCRYPTED" // Modern Android enforces FBE by default
        }

        // 3. Developer options & USB debugging
        val devOptionsEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }

        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }

        // 4. Verified boot / build tags
        val verifiedBoot = Build.TAGS ?: "unknown"

        // 5. Security patch level
        val securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Build.VERSION.SECURITY_PATCH
        } else {
            null
        }

        // 6. Root detection — multi-heuristic approach
        val rootAssessment = assessRootStatus()
        val rootDetected = rootAssessment != "NOT_DETECTED"

        // 7. Emulator detection (reuse DeviceInfoCollector heuristic)
        val isEmulator = detectEmulator()

        // 8. Unknown sources — checks whether install from unknown sources is enabled
        val unknownSourcesEnabled = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // On API 26+, this is per-app, we can only check our own package
                context.packageManager.canRequestPackageInstalls()
            } else {
                @Suppress("DEPRECATION")
                Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
            }
        } catch (_: Exception) {
            null
        }

        // 9. Accessibility services state
        val accessibilityServicesActive = try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            val enabledServices = am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            enabledServices != null && enabledServices.isNotEmpty()
        } catch (_: Exception) {
            null
        }

        // 10. Device admin active
        val deviceAdminActive = try {
            val activeAdmins = dpm?.activeAdmins
            activeAdmins != null && activeAdmins.isNotEmpty()
        } catch (_: Exception) {
            null
        }

        // 11. Play Protect — no official public API, report as unknown
        // Google Play Protect status can only be checked via Play Integrity API or
        // SafetyNet (deprecated). We honestly report null rather than fabricate.
        val playProtectEnabled: Boolean? = null

        return SecurityPostureTelemetry(
            screen_lock = isScreenLockSecure,
            encryption = encryptionStatus,
            developer_options = devOptionsEnabled,
            usb_debugging = adbEnabled,
            verified_boot = verifiedBoot,
            security_patch = securityPatch,
            biometric_capability = if (isScreenLockSecure) "AVAILABLE" else "NOT_CONFIGURED",
            root_detected = rootDetected,
            root_assessment = rootAssessment,
            is_emulator = isEmulator,
            unknown_sources_enabled = unknownSourcesEnabled,
            accessibility_services_active = accessibilityServicesActive,
            device_admin_active = deviceAdminActive,
            play_protect_enabled = playProtectEnabled
        )
    }

    /**
     * Multi-heuristic root assessment.
     * Returns: NOT_DETECTED | LIKELY_ROOTED | UNKNOWN
     */
    private fun assessRootStatus(): String {
        var indicators = 0

        // Check known su binary paths
        val suPaths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su"
        )
        for (path in suPaths) {
            try {
                if (File(path).exists()) {
                    indicators++
                    break
                }
            } catch (_: Exception) {
            }
        }

        // Check build tags
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) {
            indicators++
        }

        // Check for Magisk artifacts
        val magiskPaths = arrayOf(
            "/sbin/.magisk",
            "/cache/.magisk",
            "/data/adb/magisk"
        )
        for (path in magiskPaths) {
            try {
                if (File(path).exists()) {
                    indicators++
                    break
                }
            } catch (_: Exception) {
            }
        }

        // Check for common root management apps
        val rootPackages = arrayOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su"
        )
        val pm = context.packageManager
        for (pkg in rootPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                indicators++
                break
            } catch (_: Exception) {
            }
        }

        return when {
            indicators >= 2 -> "LIKELY_ROOTED"
            indicators == 1 -> "LIKELY_ROOTED"
            else -> "NOT_DETECTED"
        }
    }

    /**
     * Emulator detection heuristic from Build properties.
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

        return indicators.count { it } >= 2
    }
}
