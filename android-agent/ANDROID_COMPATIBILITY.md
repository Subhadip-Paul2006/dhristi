# Drishti Android Agent — Platform Compatibility Matrix

## Supported Android Versions

| Android Version | API Level | Support Status | Primary SELinux / Security Constraints |
| :--- | :--- | :--- | :--- |
| **Android 14 (UpsideDownCake)** | API 34 | **Full Support** | Foreground service types mandatory (`connectedDevice`), MAC address randomization enforced, `/proc/stat` global access denied, `POST_NOTIFICATIONS` runtime permission. |
| **Android 15 (VanillaIceCream)** | API 35 | **Target & Reference** | Strict 16KB page size readiness, edge-to-edge enforcement, strict foreground service timeout policies, encrypted shared preferences with AES-256-GCM. |
| **Android 16 (Baklava)** | API 36 | **Future-Proofed** | Embedded photo picker and privacy sandbox alignment, non-SDK interface restrictions enforced, granular background work scheduling. |

---

## Technical Telemetry & Permission Governance

### 1. CPU & Hardware Architecture
- **SELinux Boundary**: Non-root Android applications cannot access `/proc/stat` or `/sys/devices/system/cpu/` to sample per-core CPU cycles.
- **Drishti Implementation**:
  - `CpuCollector` inspects available hardware cores truthfully via `Runtime.getRuntime().availableProcessors()`.
  - Architecture is reported via `Build.SUPPORTED_ABIS` (e.g., `arm64-v8a`).
  - Sets `per_core_supported = false` and `usage_percent = null` when SELinux blocks reading `/proc/stat`.
  - **No Fake Data Guarantee**: Zero synthetic per-core numbers are generated.

### 2. Process Visibility
- **Android Sandboxing**: Starting with Android 7 and tightened in Android 14+, `/proc` is mounted with `hidepid=2` or strict SELinux labels preventing apps from inspecting `/proc/[pid]` of other applications.
- **Drishti Implementation**:
  - Inspects own process telemetry via `Process.myPid()` and memory allocation (`Runtime.getRuntime().totalMemory()`, `Debug.getPss()`).
  - Identifies foreground application usage **only** when the user explicitly grants `PACKAGE_USAGE_STATS` in Android Settings (`AppOpsManager.OPSTR_GET_USAGE_STATS`).
  - Never attempts root privilege escalation or unsupported private API calls.

### 3. Application Inventory & Vulnerability Correlation
- **Package Visibility (`<queries>`)**: Android 11+ restricts package querying unless explicitly declared in `AndroidManifest.xml`.
- **Drishti Implementation**:
  - Declares `<intent><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent>` to inspect user-facing launchable applications.
  - Synthesizes `installed_software` entries (`name`, `version`, `vendor`) sent to Drishti SOC for live correlation against CISA KEV and NVD databases.
  - Normalizer recognizes canonical package names (`com.android.chrome`, `org.mozilla.firefox`, `org.videolan.vlc`, `com.brave.browser`).

### 4. Network Presence & MAC Address
- **MAC Address Randomization**: Android 10+ randomizes MAC addresses on Wi-Fi and strictly returns dummy values (`02:00:00:00:00:00`) for non-system apps.
- **Drishti Implementation**:
  - `mac` field is set to `null` on Android agents.
  - Identity is pinned cryptographically using a persistent UUID stored in `EncryptedSharedPreferences` backed by the Android Keystore.
  - Local network presence is determined via `ConnectivityManager.getLinkProperties()`.

### 5. Defensive Network Destination Monitoring
- **Defensive VpnService (`DrishtiVpnService`)**:
  - Uses standard Android `VpnService` API with user opt-in (`VpnService.prepare()`).
  - Evaluates outbound destination IP addresses and ports to identify suspicious C2 communication.
  - **Zero Payload Inspection**: Preserves complete end-user privacy by never storing or logging packet payload content.

### 6. Defensive Remediation Model
- **No Inappropriate Shell Executables**: Android does not feature `apt-get`, `yum`, or arbitrary desktop package managers.
- **Drishti Implementation**:
  - The Drishti remediation engine checks `os_name == "android"` or `vendor == "Android"`.
  - Refuses shell generation with `sudo`, `apt-get`, or root playbooks.
  - Delivers defensive MDM policies, Google Play Store upgrade directives, or security patch recommendations.
