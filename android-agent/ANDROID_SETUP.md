# Drishti Android Agent — Setup Guide

## Prerequisites

- **Android device**: API 34+ (Android 14) or emulator with API 34+
- **ADB**: Android Debug Bridge installed and in PATH
- **Drishti backend**: Running at a reachable URL (e.g. `http://10.0.2.2:8000` for emulator)

---

## Step 1: Install the APK

```bash
# Install (replace with your device if multiple connected)
adb install -r dist/Drishti-Android-Agent-debug.apk

# Verify installation
adb shell pm list packages | grep drishti
```

## Step 2: Configure Backend URL

On the device, open the Drishti Agent app. On first launch you will see a settings field
for the Backend URL. Enter your SOC backend address, e.g.:
- Emulator: `http://10.0.2.2:8000`
- Real device on local network: `http://192.168.1.x:8000`

## Step 3: Grant UsageStats Permission (Required for ForegroundAppCollector)

```bash
adb shell appops set com.drishti.agent PACKAGE_USAGE_STATS allow
```

OR manually: **Settings → Apps → Special app access → Usage access → Drishti Agent → Enable**

## Step 4: Start Demo Mode Pairing

1. Enable **Demo Mode** toggle in the app.
2. Tap **Start Pairing**.
3. The agent will display pairing code `ABCD-1234`.
4. In the Drishti SOC Web UI, open **Pair Endpoint** and enter `ABCD-1234`.
5. Click **Authorize** — the agent will transition to `CONNECTED`.

> **Note**: Demo Mode requires `DRISHTI_DEMO_MODE=true` on the backend server.

## Step 5: Enable Defensive Network Shield (Optional)

1. Tap **Enable Network Shield** in the app.
2. Accept the Android VPN consent dialog.
3. The shield icon in the notification bar confirms it is active.
4. Network flow metadata will appear in the SOC Live Watch drawer.

## Step 6: Verify in SOC Dashboard

- Open the Drishti web interface.
- Navigate to **Live Watch**.
- Your Android device should appear with platform badge `android`.
- Click the device to expand the detail drawer showing:
  - Device Info, CPU, Memory, Storage, Battery
  - Security Posture
  - Foreground App (if UsageStats granted)
  - Network Flows (if VPN shield active)
  - Capability Matrix

---

## Troubleshooting

| Symptom | Solution |
|---|---|
| App not visible in Live Watch | Check backend URL is correct and reachable from device |
| Foreground app always null | Grant PACKAGE_USAGE_STATS via ADB or Settings |
| VPN shield won't start | Accept the VPN consent dialog; check VPN is not already active |
| Pairing code ABCD-1234 rejected | Ensure backend has `DRISHTI_DEMO_MODE=true` environment variable |
