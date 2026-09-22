# Drishti Android Agent — Platform Limitations & Sandbox Constraints

This document honestly documents what the Drishti Android Agent CANNOT do due to Android OS
sandboxing, SELinux policy, and API restrictions. All limitations are transparently reported
in the `capability_status` field of the telemetry batch.

---

## 1. CPU Usage (`/proc/stat`)

**Status: RESTRICTED**
- On Android 10+ (API 29+), SELinux policy blocks unprivileged access to `/proc/stat`.
- `CpuCollector.collect()` returns `usage_percent = null` and `per_core_supported = false`.
- The number of CPU cores (`Runtime.getRuntime().availableProcessors()`) and max/min clock
  frequencies from `/sys/devices/system/cpu/cpu0/cpufreq/` are reported where accessible.
- `thermal_status` is obtained from `PowerManager.getCurrentThermalStatus()` (API 29+).

## 2. Hardware MAC Address

**Status: RESTRICTED**
- On Android 11+ (API 30+), `WifiInfo.getMacAddress()` returns the randomized MAC `02:00:00:00:00:00`.
- The `EndpointIdentity.mac` field is always `null` on Android agents — this is intentional and correct.

## 3. Global Process Listing

**Status: RESTRICTED**
- `ActivityManager.getRunningAppProcesses()` only returns processes visible to the calling app
  since Android 7 (API 24). Global process listing requires root or a system-privileged app.
- `ProcessCollector` reports what is visible (primarily the Drishti agent itself and a small set
  of system-provided summaries). All processes are categorized with `capability_status = "SANDBOXED"`.

## 4. Browser Tab & History Visibility

**Status: PLATFORM_RESTRICTED**
- Android's app sandbox prevents one app from reading another app's internal state.
- Browser tab titles, URLs, and history are completely inaccessible without root.
- `BrowserVisibility` accurately reports: installed browsers (via `PackageManager`), whether
  Chrome is present, and which browser is in the foreground (via `UsageStatsManager` if permitted).
- `tab_visibility_capability = "PLATFORM_RESTRICTED"` and `history_capability = "PLATFORM_RESTRICTED"`.

## 5. Network Socket Table (`/proc/net/tcp`)

**Status: RESTRICTED**
- On Android 10+ (API 29+), apps cannot read `/proc/net/tcp` due to VFS restrictions.
- The agent uses VpnService-based flow tracking to observe destination IP/port metadata
  for outbound packets. This requires explicit user VPN consent.
- No payload inspection occurs — only destination IP, port, protocol, and packet count.

## 6. Keystore & Cryptographic Keys

**Status: SUPPORTED**
- The Drishti agent uses Android Keystore System (`KeyStore.getInstance("AndroidKeyStore")`)
  to store the agent authentication token in SecureStorage.
- Keys are hardware-backed on devices with a Trusted Execution Environment (TEE) or StrongBox.
- Keys do not leave the secure hardware — never transmitted in telemetry.

## 7. Android Version Compatibility Matrix

| Android Version | API Level | Notes |
|---|---|---|
| Android 14 | 34 | Minimum supported. Foreground service types mandatory. |
| Android 15 | 35 | Full support. All APIs stable. |
| Android 16 | 36 | Designed to remain compatible. No breaking API changes anticipated. |
| Android 17-19+ | 37-39 | Forward-compatible design. Will require validation when released. |
