# 🔧 Drishti: Troubleshooting & Diagnostic Guide

> **Parent Specification:** [SETUP.md](../../SETUP.md) · [USAGE.md](../../USAGE.md)  
> **Status:** Operational Runbook

---

## 1. Quick Diagnostic Checklist

If an issue occurs, run through this five-point diagnostic sequence:

1. **Backend Health Check:**
   ```bash
   curl http://127.0.0.1:8000/api/health/ready
   # Expected response: {"status":"ready","database_connected":true,...}
   ```
2. **Frontend Console:**
   - Open browser developer tools (`F12` or `Cmd+Option+I`) and check the **Console** tab for CORS errors or network failures.
3. **Database Locks:**
   - If using SQLite in high-concurrency environments, verify `drishti.db` has write permissions and is not locked by an external viewer.
4. **Port Conflicts:**
   - Verify port `8000` (FastAPI) and port `5173` (Vite) are not occupied by existing processes.
5. **Agent Pairing State:**
   - Check `http://localhost:5173/assets` to verify whether the agent is reporting an `ONLINE` or `OFFLINE` status.

---

## 2. Common Errors & Resolution

### Issue 1: "Npcap / WinPcap Not Found" (Windows Packet Sniffing)
- **Symptom:** Running `drishti_watch.py` or initiating a packet trace logs a warning: `Scapy warning: No libpcap provider found!`.
- **Cause:** Windows requires the Npcap kernel driver to capture raw Ethernet frames.
- **Resolution:**
  1. Download the free installer from [npcap.com](https://npcap.com/#download).
  2. During installation, select **"Install Npcap in WinPcap API-compatible Mode"**.
  3. Restart the PowerShell terminal.

---

### Issue 2: BPF Permission Denied (macOS)
- **Symptom:** Running the passive watcher on macOS returns `PermissionError: [Errno 13] Permission denied: '/dev/bpf0'`.
- **Cause:** macOS restricts access to Berkley Packet Filter devices to the `root` user or members of `access_bpf`.
- **Resolution:**
  ```bash
  # Option A: Run capture with sudo:
  sudo python agent/drishti_watch.py

  # Option B: Grant persistent user access to /dev/bpf:
  sudo chown $USER /dev/bpf*
  ```

---

### Issue 3: CORS Blocking Dashboard Requests
- **Symptom:** Browser console shows `Access to fetch at 'http://127.0.0.1:8000/api/...' from origin 'http://localhost:5173' has been blocked by CORS policy`.
- **Cause:** Frontend origin is not listed in `ALLOWED_CORS_ORIGINS`.
- **Resolution:**
  - Verify `.env` contains:
    ```text
    ALLOWED_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
    ```
  - Restart the backend server.

---

### Issue 4: Android Agent Pairing Timeout
- **Symptom:** Mobile app hangs on "Connecting to Controller...".
- **Cause:** The mobile device cannot reach `127.0.0.1` on your laptop (loopback points to the phone itself).
- **Resolution:**
  1. Find your development laptop's local LAN IP:
     - Windows: `ipconfig` (e.g. `192.168.1.15`)
     - macOS/Linux: `ifconfig`
  2. On the Android device, set the Server URL to `http://192.168.1.15:8000`.
  3. Ensure both laptop and phone are connected to the same Wi-Fi network and laptop firewall allows inbound port 8000.
  4. If using Android Emulator via ADB: Use `http://10.0.2.2:8000`.

---

### Issue 5: Missing or Expired Anthropic API Key
- **Symptom:** Clicking "Generate Mitigation Playbook" returns an error: `AI Generation Failed: AuthenticationError`.
- **Cause:** `ANTHROPIC_API_KEY` is either missing in `.env` or has exceeded quota.
- **Resolution:**
  - In local development, ensure `.env` contains a valid key: `ANTHROPIC_API_KEY=sk-ant-api03-...`.
  - In Vercel Demo Mode, this is handled gracefully by synthetic fallback playbooks with zero API requirements.
