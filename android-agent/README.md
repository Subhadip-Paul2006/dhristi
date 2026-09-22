# Drishti Android Endpoint Agent

The **Drishti Android Endpoint Agent** is a production-grade, permission-aware cybersecurity telemetry agent built for modern Android platforms (**Android 14 / API 34**, **Android 15 / API 35**, and **Android 16 / API 36**).

It extends the Drishti cybersecurity platform to mobile endpoints, providing real-time presence, telemetry collection, vulnerability correlation, and defensive security posture tracking without compromising the Android security model or fabricating telemetry.

---

## Key Features

1. **Deterministic Pairing**:
   - Generates a 6-character ephemeral pairing code.
   - Authorizes securely through the existing Drishti Web SOC console (`/api/endpoint/pairing/pair`).
   - Stores JWT authentication tokens in hardware-backed `EncryptedSharedPreferences` via the Android Keystore (`MasterKey.KeyScheme.AES256_GCM`).

2. **Continuous Presence & Heartbeat**:
   - Runs a lightweight Android Foreground Service (`foregroundServiceType="connectedDevice"`) with low battery overhead.
   - Transmits periodic heartbeats every 20 seconds to `/api/endpoint/heartbeat`.
   - Exponential backoff (3s to 60s) with automatic reconnection upon network state changes.

3. **Production Telemetry Pipeline**:
   - **Hardware & Resource Telemetry**: CPU core count, architecture (`arm64-v8a`), RAM allocation, internal storage utilization, battery percentage, charging state, temperature, and link speed.
   - **Security Posture**: Root detection (`test-keys`, `su` binary discovery), SELinux enforcing state, lock screen protection, storage encryption, developer options, and USB debugging flags.
   - **Application Inventory**: Queries user and system packages cleanly via `<queries>` declarations in compliance with Android 11+ package visibility rules.

4. **Honest Platform Boundaries**:
   - Does **not** fabricate per-core CPU loads or fake desktop process trees when SELinux enforces security barriers.
   - Does **not** invent or guess CVE IDs.
   - MAC address access is never attempted (set to `null` to respect Android 11+ privacy restrictions).

5. **Defensive Network Shield (`DrishtiVpnService`)**:
   - Optional, user-consented destination tracking via local `VpnService` interface.
   - Preserves complete user privacy: zero packet payload logging, inspecting only IP headers for destination anomaly detection.

6. **Defensive Remediation**:
   - Refuses inappropriate desktop commands (`sudo`, `apt-get`, `yum`, shell scripts) against Android devices.
   - Produces defensive MDM remediation playbooks and Google Play Store update instructions.

---

## Directory Structure

```
android-agent/
├── app/
│   ├── build.gradle.kts          # Dependencies & SDK config (minSdk 34, targetSdk 35)
│   ├── proguard-rules.pro        # ProGuard / R8 rules
│   └── src/
│       ├── main/
│       │   ├── AndroidManifest.xml
│       │   ├── java/com/drishti/agent/
│       │   │   ├── DrishtiApplication.kt
│       │   │   ├── MainActivity.kt
│       │   │   ├── collectors/   # CPU, RAM, Storage, Battery, Network, Apps, Security
│       │   │   ├── models/       # Serialization data classes
│       │   │   ├── pairing/      # Pairing state machine & manager
│       │   │   ├── permissions/  # Progressive permissions manager
│       │   │   ├── services/     # EndpointForegroundService & DrishtiVpnService
│       │   │   ├── storage/      # SecureStorage with Keystore AES-256
│       │   │   └── transport/    # DrishtiApiClient, HeartbeatManager, TelemetryManager
│       │   └── res/              # Layouts, vector icons, themes, and colors
│       └── test/java/com/drishti/agent/
│           ├── ApiClientTest.kt
│           ├── CollectorPermissionTest.kt
│           ├── IdentityTest.kt
│           ├── OfflineRecoveryTest.kt
│           ├── PairingTest.kt
│           └── TelemetrySerializationTest.kt
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
├── ANDROID_COMPATIBILITY.md
└── README.md
```

---

## Building and Running

### Prerequisites
- **JDK 17** or **JDK 21/23**
- **Android SDK Platform 35** and Build-Tools 35.0.0
- **Android Studio Jellyfish / Koala** or Gradle 8.11+

### Build via Gradle
```bash
cd android-agent
./gradlew assembleDebug
```
The resulting debug APK will be generated at:
`app/build/outputs/apk/debug/app-debug.apk`

### Running Unit Tests
```bash
./gradlew testDebugUnitTest
```

---

## Pairing with Drishti SOC

1. Start the Drishti backend server (`uvicorn app.main:app --port 8000`).
2. Launch the **Drishti Agent** application on the Android device or emulator.
3. Configure the Server URL (e.g., `http://10.0.2.2:8000` on emulator, or LAN IP for physical device).
4. Tap **Initiate Pairing**. Note the 6-character code displayed.
5. In the **Drishti Web Console**, navigate to **Endpoint Agents** and enter the code to authorize.
6. The Android agent will immediately receive its authentication token, start the foreground service, and begin transmitting heartbeats and telemetry to the Live Watch drawer.
