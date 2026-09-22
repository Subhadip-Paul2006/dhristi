# Drishti Android Agent — Test Report

**Date**: 2026-09-22  
**Build**: `app-debug.apk` (17.3 MB)  
**Package**: `com.drishti.agent.debug`  
**Version**: `0.1.0`  
**Min SDK**: 34 (Android 14)  
**Target SDK**: 35 (Android 15)  

---

## Android Unit Tests

**Command**: `./gradlew.bat testDebugUnitTest --no-daemon`  
**Result**: ✅ BUILD SUCCESSFUL — 26 tasks, all UP-TO-DATE / PASSED

| Test Class | Tests | Result |
|---|---|---|
| `ApiClientTest` | 4 | ✅ PASS |
| `PairingTest` | 2 | ✅ PASS |
| `CollectorPermissionTest` | 2 | ✅ PASS |
| `IdentityTest` | 2 | ✅ PASS |
| `OfflineRecoveryTest` | 3 | ✅ PASS |
| `TelemetrySerializationTest` | 1 | ✅ PASS |

---

## Backend Integration Tests

**Command**: `pytest tests/test_android_endpoint.py -v`  
**Result**: ✅ 5 passed, 1 warning in 10.99s

| Test | Result |
|---|---|
| `test_android_pairing_initialization` | ✅ PASS |
| `test_android_pairing_workflow_and_device_upsert` | ✅ PASS |
| `test_android_telemetry_extended_ingestion` | ✅ PASS |
| `test_android_defensive_remediation_guardrails` | ✅ PASS |
| `test_android_demo_mode_and_expanded_telemetry` | ✅ PASS |

---

## Telemetry Feature Matrix

| Feature | Collector | Status | Notes |
|---|---|---|---|
| Device Info (model, build, ABI) | `DeviceInfoCollector` | ✅ Implemented | Full Android build metadata |
| CPU cores & thermal | `CpuCollector` | ✅ Implemented | Usage% null (SELinux restricted) |
| RAM / low-memory | `MemoryCollector` | ✅ Implemented | ActivityManager.MemoryInfo |
| Internal / external storage | `StorageCollector` | ✅ Implemented | StatFs |
| Battery (%, temp, charging type) | `BatteryCollector` | ✅ Implemented | Full BatteryManager fields |
| Network (SSID, DNS, IPv6, bytes) | `NetworkCollector` | ✅ Implemented | ConnectivityManager + TrafficStats |
| Installed app inventory | `AppCollector` | ✅ Implemented | PackageManager, signing SHA256 |
| App usage / foreground app | `ForegroundAppCollector` | ✅ Implemented | UsageStatsManager (permission required) |
| Browser visibility | `AppCollector.collectBrowserVisibility()` | ✅ Implemented | Installed + foreground only |
| Security posture | `SecurityCollector` | ✅ Implemented | Lock, encryption, ADB, root, Play Protect |
| Uptime & boot time | `DeviceInfoCollector.collectUptime()` | ✅ Implemented | SystemClock.elapsedRealtime() |
| Network flow metadata | `DrishtiVpnService` + `NetworkFlowCollector` | ✅ Implemented | VPN-based, destination only |
| Capability matrix | `CapabilityMatrixCollector` | ✅ Implemented | Transparent honest reporting |
| Processes | `ProcessCollector` | ✅ Implemented | Sandboxed — app-visible only |
| MAC address | N/A | ⚠️ Platform Restricted | Always null on Android 11+ |
| Global /proc/stat CPU | N/A | ⚠️ SELinux Blocked | usage_percent = null |
| Browser tab/history | N/A | ⚠️ Sandboxed | Platform-restricted per Android design |

---

## APK Artifact

| Property | Value |
|---|---|
| File | `dist/Drishti-Android-Agent-debug.apk` |
| Size | 17.3 MB (17,314,176 bytes) |
| Build type | debug (signed with debug keystore) |
| Built | 2026-09-22 14:33:05 |
