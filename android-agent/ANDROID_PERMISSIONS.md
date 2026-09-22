# Drishti Android Agent — Permission Reference

This document lists every Android permission declared by the Drishti endpoint agent,
explains why it is needed, which API level it applies to, the grant flow, and what
the agent gracefully degrades to when the permission is absent.

---

## 1. Normal Permissions (auto-granted at install)

| Permission | Purpose | API Level |
|---|---|---|
| `INTERNET` | Send telemetry and heartbeat to backend SOC | All |
| `ACCESS_NETWORK_STATE` | Detect network type (Wi-Fi/Mobile/VPN) for `NetworkCollector` | All |
| `ACCESS_WIFI_STATE` | Read SSID, BSSID, link speed for `NetworkCollector` | All |
| `FOREGROUND_SERVICE` | Keep `EndpointForegroundService` alive in background | API 28+ |
| `FOREGROUND_SERVICE_CONNECTED_DEVICE` | Required foreground type for Android 14+ (API 34+) | API 34+ |
| `POST_NOTIFICATIONS` | Show persistent foreground notification (required Android 13+) | API 33+ |

---

## 2. Runtime Permissions (user must explicitly grant)

### `PACKAGE_USAGE_STATS`
- **Purpose**: `ForegroundAppCollector` — identify the foreground application via `UsageStatsManager`.
- **Grant flow**: Navigate to Settings > Apps > Special app access > Usage access and toggle on "Drishti Agent".
- **Manual ADB step**:
  ```
  adb shell appops set com.drishti.agent PACKAGE_USAGE_STATS allow
  ```
- **Graceful degradation**: Returns `ForegroundAppTelemetry(package_name = null, capability_status = "PERMISSION_REQUIRED")`.

### `BIND_VPN_SERVICE` (VPN Consent)
- **Purpose**: `DrishtiVpnService` — passive destination IP/port metadata tracking.
- **Grant flow**: User taps "Enable Defensive Shield" in-app; Android shows system VPN consent dialog.
- **Graceful degradation**: `network_flows` in telemetry is empty. Heartbeat and standard telemetry are unaffected.

---

## 3. Permissions NOT Requested (and why)

| Permission | Reason Not Requested |
|---|---|
| `READ_PHONE_STATE` | IMEI access has no monitoring value and is restricted on API 29+. |
| `ACCESS_FINE_LOCATION` | Wi-Fi SSID available via `ACCESS_WIFI_STATE` on API 26+. |
| `READ_CONTACTS` | Not applicable to endpoint security monitoring. |
| `CAMERA` / `RECORD_AUDIO` | Not applicable — telemetry is network/system state only. |
| `READ_EXTERNAL_STORAGE` | Storage telemetry uses `StatFs` — no broad file access needed. |

---

## 4. ADB Commands: Manual Permission Setup (Lab/Hackathon)

```bash
# Install the debug APK
adb install -r dist/Drishti-Android-Agent-debug.apk

# Grant UsageStats access (required for ForegroundAppCollector)
adb shell appops set com.drishti.agent PACKAGE_USAGE_STATS allow

# Launch main activity
adb shell am start -n com.drishti.agent.debug/.MainActivity
```
