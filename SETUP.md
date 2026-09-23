# 🚀 Drishti — Complete Installation & Configuration Manual (SETUP.md)

> **Document Version:** 1.0.0  
> **Target Audience:** Security Operations Engineers, System Administrators, DevOps Engineers, Lab Evaluators  
> **Scope:** Full step-by-step installation, platform-specific agent configuration, network firewall hardening, pairing mechanics, and verification procedures for the Drishti Cybersecurity Platform.

---

## 📑 Manual Table of Contents

- [Section 0 — Autonomous AI Agent Setup Protocol (Auto-Detect OS & Install)](#section-0--autonomous-ai-agent-setup-protocol-auto-detect-os--install)
- [Section A — Prerequisites](#section-a--prerequisites)
- [Section B — Clone & Workspace Preparation](#section-b--clone--workspace-preparation)
- [Section C — Environment Configuration (.env)](#section-c--environment-configuration-env)
- [Section D — Backend Setup (FastAPI Server)](#section-d--backend-setup-fastapi-server)
- [Section E — Frontend Setup (React/Vite Console)](#section-e--frontend-setup-reactvite-console)
- [Section F — Windows Endpoint Setup (Agent .exe)](#section-f--windows-endpoint-setup-agent-exe)
- [Section G — macOS Endpoint Setup (Agent .pkg)](#section-g--macos-endpoint-setup-agent-pkg)
- [Section H — Linux Endpoint Support Status](#section-h--linux-endpoint-support-status)
- [Section I — Android Endpoint Setup (APK)](#section-i--android-endpoint-setup-apk)
- [Section J — Target Device Setup Matrix](#section-j--target-device-setup-matrix)
- [Section K — Network & Routing Configuration](#section-k--network--routing-configuration)
- [Section L — Firewall Configuration Rules](#section-l--firewall-configuration-rules)
- [Section M — Pairing & Authentication Mechanics](#section-m--pairing--authentication-mechanics)
- [Section N — Running an End-to-End Verification Demo](#section-n--running-an-end-to-end-verification-demo)
- [Section O — Comprehensive Troubleshooting Matrix](#section-o--comprehensive-troubleshooting-matrix)
- [Section P — Security, Privacy & Consent Boundaries](#section-p--security-privacy--consent-boundaries)
- [Section Q — Build Artifacts & Verification](#section-q--build-artifacts--verification)
- [Section R — Architecture & Flow Diagrams](#section-r--architecture--flow-diagrams)
- [Section S — External Reference Integration (GitHub Archive)](#section-s--external-reference-integration-github-archive)
- [Section T — Final Documentation Audit](#section-t--final-documentation-audit)

---

## SECTION 0 — AUTONOMOUS AI AGENT SETUP PROTOCOL (AUTO-DETECT OS & INSTALL)

> [!IMPORTANT]
> **OPERATIONAL MANDATE FOR AI AGENTS (Antigravity, Cursor, Windsurf, Devin, Copilot, Claude Code, Aider, etc.)**:  
> When an operator passes you this repository and asks you to *"set up the project"*, *"install dependencies"*, *"prepare the system"*, or simply hands you `SETUP.md`:
> 
> **DO NOT MERELY OUTPUT A SUMMARY OR DUMP TEXT INSTRUCTIONS FOR THE OPERATOR TO RUN MANUALLY.**  
> **YOU MUST AUTONOMOUSLY EXECUTE THE INSTALLATION COMMANDS FOR THE DETECTED OPERATING SYSTEM.**
> 
> Use your terminal execution tools (`run_command`, `bash`, `powershell`, or subagent) to fingerprint the operating system, remediate missing packages, bootstrap the virtual environments, and verify platform readiness.

---

### ⚡ Option 1: One-Command Autonomous Script Execution (Fastest & Recommended)

Drishti includes pre-built automated setup scripts designed specifically for AI agents and automated CI/CD environments.

#### 🪟 On Windows (PowerShell):
Execute the automated Windows setup script:
```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```
*What this script does autonomously:*
1. Fingerprints Windows version and architecture (x64/ARM64).
2. Verifies Python 3.11+, Node.js 18+ (LTS), and Git. If any are missing, auto-installs them via `winget`.
3. Creates `.env` from `.env.example` with local defaults (`APP_ENV=local`, `DRISHTI_DEMO_MODE=true`).
4. Creates `server\venv`, upgrades pip, and installs all `server\requirements.txt` dependencies.
5. Installs React/Vite dependencies via `npm install` inside `web\`.
6. Checks Windows Endpoint Agent binary (`dist\Drishti-Endpoint-Agent-Windows.exe`).
7. Performs import validation and prints launch instructions.

#### 🐧 On Linux or 🍏 On macOS (Bash / Zsh):
Make executable and run the automated Unix setup script:
```bash
chmod +x setup.sh && ./setup.sh
```
*(On macOS, you can also launch both servers immediately with `./start-mac.sh` after setup).*

---

### 🛠️ Option 2: Step-by-Step Autonomous Execution Decision Tree

If you are an AI Agent executing commands step-by-step or in a granular tool execution loop, follow this strict 8-step decision tree:

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    START(["🤖 AI Agent Invoked with SETUP.md"]) --> DETECT["Step 1: Fingerprint OS & Architecture"]
    
    DETECT --> OS_CHECK{Identify OS}
    OS_CHECK -->|Windows| WIN_PREREQ["Step 2a: Check/Install via winget<br/>• Python 3.11+<br/>• Node.js 18+ (LTS)<br/>• Git"]
    OS_CHECK -->|macOS| MAC_PREREQ["Step 2b: Check/Install via Homebrew<br/>• brew install python@3.11<br/>• brew install node@20<br/>• brew install git"]
    OS_CHECK -->|Linux| LINUX_PREREQ["Step 2c: Check/Install via apt / dnf / pacman<br/>• python3.11 + python3.11-venv + pip<br/>• nodejs 18+ + npm<br/>• git + curl"]

    WIN_PREREQ --> ENV_INIT["Step 3: Initialize Root .env File<br/>(Copy .env.example if missing)"]
    MAC_PREREQ --> ENV_INIT
    LINUX_PREREQ --> ENV_INIT

    ENV_INIT --> BACKEND["Step 4: Bootstrap Backend (server/)<br/>• Create venv<br/>• Upgrade pip<br/>• pip install -r server/requirements.txt"]
    BACKEND --> FRONTEND["Step 5: Bootstrap Frontend (web/)<br/>• cd web && npm install"]
    FRONTEND --> AGENT_CHECK["Step 6: Prepare Endpoint Agent<br/>• Check dist/ binary or endpoint-agent/venv"]
    AGENT_CHECK --> HEALTH["Step 7: Verification & Health Check<br/>• Validate FastAPI & Vite builds"]
    HEALTH --> REPORT(["Step 8: Output Ready URLs & Start Services"])
```

#### Step 1: Detect Operating System & Environment
Execute the appropriate fingerprint command:
- **Windows (PowerShell)**:
  ```powershell
  $PSVersionTable.OS; (Get-CimInstance Win32_OperatingSystem).Caption; [Environment]::Is64BitOperatingSystem
  ```
- **macOS (Terminal)**:
  ```bash
  sw_vers; uname -m
  ```
- **Linux (Terminal)**:
  ```bash
  uname -s -m; cat /etc/os-release
  ```

---

#### Step 2: Audit & Install Missing OS Prerequisites

Check existing toolchains and invoke the native package manager to install anything missing:

| Tool | Verification Command | Windows Installation (winget) | macOS Installation (Homebrew) | Ubuntu / Debian (apt) | Fedora / RHEL (dnf) | Arch Linux (pacman) |
|---|---|---|---|---|---|---|
| **Python 3.11+** | `python --version` or `python3 --version` | `winget install Python.Python.3.11 -e --silent --accept-package-agreements --accept-source-agreements` | `brew install python@3.11` | `sudo apt update && sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip` | `sudo dnf install -y python3.11 python3.11-devel python3-pip` | `sudo pacman -S --needed --noconfirm python python-pip` |
| **Node.js 18+** | `node -v` | `winget install OpenJS.NodeJS.LTS -e --silent --accept-package-agreements --accept-source-agreements` | `brew install node@20` | `curl -fsSL https://deb.nodesource.com/setup_20.x \| sudo -E bash - && sudo apt install -y nodejs` | `sudo dnf install -y nodejs npm` | `sudo pacman -S --needed --noconfirm nodejs npm` |
| **Git** | `git --version` | `winget install Git.Git -e --silent --accept-package-agreements --accept-source-agreements` | `brew install git` | `sudo apt install -y git` | `sudo dnf install -y git` | `sudo pacman -S --needed --noconfirm git` |
| **ADB & Java 17** *(Optional for Android)* | `adb version` | `winget install Google.PlatformTools EclipseAdoptium.Temurin.17.JDK` | `brew install android-platform-tools openjdk@17` | `sudo apt install -y adb openjdk-17-jdk` | `sudo dnf install -y android-tools java-17-openjdk` | `sudo pacman -S --needed --noconfirm android-tools jdk17-openjdk` |

---

#### Step 3: Initialize Root Environment (`.env`)

Verify that the root `.env` exists. If missing, copy from `.env.example`:

- **Windows PowerShell**:
  ```powershell
  if (-not (Test-Path .env)) { Copy-Item .env.example .env }
  ```
- **Linux / macOS Bash**:
  ```bash
  [ ! -f .env ] && cp .env.example .env
  ```

*(Ensure `APP_ENV=local`, `DATABASE_URL=sqlite:///./drishti.db`, and `DRISHTI_DEMO_MODE=true` are active for immediate local testing).*

---

#### Step 4: Bootstrap Backend Environment (`server/`)

Execute in the repository root:

- **Windows PowerShell**:
  ```powershell
  # 1. Create virtual environment
  python -m venv server\venv
  
  # 2. Upgrade pip and install server dependencies
  .\server\venv\Scripts\python.exe -m pip install --upgrade pip --quiet
  .\server\venv\Scripts\pip.exe install -r server\requirements.txt --quiet
  
  # 3. Verify backend runtime import
  .\server\venv\Scripts\python.exe -c "import fastapi, uvicorn, sqlalchemy; print('✓ Backend Dependencies Verified Successfully!')"
  ```

- **Linux / macOS Bash**:
  ```bash
  # 1. Create virtual environment
  python3 -m venv server/venv
  
  # 2. Upgrade pip and install server dependencies
  server/venv/bin/python -m pip install --upgrade pip --quiet
  server/venv/bin/pip install -r server/requirements.txt --quiet
  
  # 3. Verify backend runtime import
  server/venv/bin/python -c "import fastapi, uvicorn, sqlalchemy; print('✓ Backend Dependencies Verified Successfully!')"
  ```

---

#### Step 5: Bootstrap Frontend SOC Console (`web/`)

Execute in the repository root:

- **Cross-Platform (Windows / Linux / macOS)**:
  ```bash
  # Install web dependencies using npm
  cd web && npm install && cd ..
  ```
  *Verify that `web/node_modules/` exists.*

---

#### Step 6: Verify Endpoint Agent Deliverables

Check the platform-appropriate agent for local testing:
- **Windows**:
  Confirm that `dist\Drishti-Endpoint-Agent-Windows.exe` exists. If building from source or testing Python agent:
  ```powershell
  if (-not (Test-Path endpoint-agent\venv)) { python -m venv endpoint-agent\venv; .\endpoint-agent\venv\Scripts\pip.exe install -r endpoint-agent\requirements.txt }
  ```
- **macOS**:
  Confirm that `dist/Drishti-Endpoint-Agent-macOS.pkg` exists.
- **Linux**:
  Passive network discovery daemon is located at `agent/drishti_watch.py`.
- **Android**:
  Confirm debug APK exists at `dist/Drishti-Android-Agent-debug.apk`.

---

#### Step 7: Final Health Verification & Service Launch

Run dry-run validations to confirm the environment is operational:

```powershell
# Quick sanity check on Windows:
.\server\venv\Scripts\python.exe -c "from app.main import app; print('✓ FastAPI App Object Loaded!')"
```
```bash
# Quick sanity check on Unix/macOS:
server/venv/bin/python -c "from app.main import app; print('✓ FastAPI App Object Loaded!')"
```

#### Launching the Services (Prompt the User or Start in Background):

1. **Backend Server (FastAPI on Port 8000)**:
   - **Windows**: `cd server; .\venv\Scripts\Activate.ps1; uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`
   - **Linux/macOS**: `cd server; source venv/bin/activate; uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`
2. **Frontend SOC Console (Vite on Port 5173)**:
   - `cd web; npm run dev`
3. **Target Endpoints**:
   - Web Console: 👉 **`http://localhost:5173`**
   - OpenAPI Docs: 👉 **`http://localhost:8000/docs`**
   - Health Probe: 👉 **`http://localhost:8000/health`**

---

## SECTION A — PREREQUISITES

Before deploying Drishti, ensure your host machines satisfy the hardware, operating system, and software runtime requirements outlined below.

### 1. Operating Systems & Hardware

| Deployment Role | Supported Operating Systems | Minimum Hardware | Recommended Hardware |
|---|---|---|---|
| **Drishti Controller / Server** | Windows 10/11, Windows Server 2022+, Ubuntu 22.04/24.04 LTS, Debian 12, macOS Sonoma (14+) | 2 CPU Cores, 4 GB RAM, 10 GB Storage | 4 CPU Cores, 8 GB RAM, 25 GB SSD |
| **Windows Endpoint** | Windows 10 (Build 19041+) or Windows 11 (x64) | 1 CPU Core, 2 GB RAM, 50 MB Storage | 2 CPU Cores, 4 GB RAM, 100 MB Storage |
| **macOS Endpoint** | macOS Monterey (12+), Ventura (13+), Sonoma (14+) | Apple Silicon (M1/M2/M3) or Intel x86_64 | 4 GB RAM, 50 MB Storage |
| **Android Endpoint** | Android 14 (API 34) or Android 15 (API 35) | Physical Device or Google Android Emulator (API 34+) | 3 GB RAM, 100 MB Free Storage |

---

### 2. Required Runtimes & Software Packages

#### A. Python 3.11+ (Server & Endpoint Build Engine)
- **WHAT**: Python runtime environment (version 3.11 or higher).
- **WHY**: Required to execute the FastAPI backend, run data analytics models (`scikit-learn`, `networkx`), execute the agent compiler (`pyinstaller`), and run discovery modules.
- **HOW TO INSTALL**:
  - **Windows**: Download from [python.org](https://www.python.org/downloads/). Check **"Add python.exe to PATH"** during installation.
    ```powershell
    winget install Python.Python.3.11
    ```
  - **Linux (Ubuntu/Debian)**:
    ```bash
    sudo apt update && sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip
    ```
  - **macOS**:
    ```bash
    brew install python@3.11
    ```

#### B. Node.js 18+ & npm 9+ (Web SOC Console)
- **WHAT**: JavaScript runtime and package manager.
- **WHY**: Required to install dependencies, run the Vite development server, compile TypeScript (`tsc`), and package production assets for the dark-mode SOC web console.
- **HOW TO INSTALL**:
  - **Windows**:
    ```powershell
    winget install OpenJS.NodeJS.LTS
    ```
  - **Linux (Ubuntu/Debian)**:
    ```bash
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
    ```
  - **macOS**:
    ```bash
    brew install node@20
    ```

#### C. Git Version Control
- **WHAT**: Distributed source code control system.
- **WHY**: Required to clone and maintain repository state.
- **HOW TO INSTALL**:
  - **Windows**: `winget install Git.Git`
  - **Linux**: `sudo apt install -y git`
  - **macOS**: `brew install git`

#### D. Android Debug Bridge (ADB) & Java 17 (For Android Endpoint Management)
- **WHAT**: Android platform development tools and OpenJDK 17.
- **WHY**: Required to sideload the Drishti Android agent APK (`adb install`), grant runtime permissions (`PACKAGE_USAGE_STATS`), and inspect Android device logcat.
- **HOW TO INSTALL**:
  - **Windows**:
    ```powershell
    winget install Google.PlatformTools
    winget install EclipseAdoptium.Temurin.17.JDK
    ```
  - **Linux**:
    ```bash
    sudo apt install -y adb openjdk-17-jdk
    ```
  - **macOS**:
    ```bash
    brew install android-platform-tools openjdk@17
    ```

#### E. Network Packet Capture Dependencies (Optional / Recommended for Live Network Watch)
- **WHAT**: Npcap (Windows), Libpcap (Linux/macOS), or Zeek / TShark.
- **WHY**: Enables the backend `capture_adapter.py` to ingest real-time packet streams on the monitored interface.
- **HOW TO INSTALL**:
  - **Windows**: Install [Npcap](https://npcap.com/) with *"Install Npcap in WinPcap API-compatible Mode"* checked, or install [Wireshark](https://www.wireshark.org/) which bundles `tshark.exe`.
  - **Linux**:
    ```bash
    sudo apt install -y libpcap-dev tshark zeek
    ```
  - **macOS**:
    ```bash
    brew install wireshark zeek
    ```

---

## SECTION B — CLONE & WORKSPACE PREPARATION

> **Note**: Execute this section on the **Drishti Controller / Server Machine**.

### 1. Clone Repository
```bash
git clone https://github.com/Subhadip-Paul2006/dhristi.git Drishti-Innofusion
cd Drishti-Innofusion
```

### 2. Workspace Directory Layout
Verify the directory contents match the expected repository structure:
```text
Drishti-Innofusion/
├── .env.example              # Sample environment template
├── compose.yaml              # Modern Docker Compose deployment
├── docker-compose.yml        # Backward-compatible compose spec
├── dist/                     # Pre-compiled distributable executables & APKs
│   ├── Drishti-Android-Agent-debug.apk
│   ├── Drishti-Endpoint-Agent-Windows.exe
│   └── Drishti-Endpoint-Agent-macOS.pkg
├── server/                   # FastAPI Backend application root
│   ├── app/                  # Application code, routers, services, models
│   ├── requirements.txt      # Backend Python dependencies
│   └── Dockerfile            # Container build spec for server
├── web/                      # React / Vite Web SOC Console root
│   ├── src/                  # React TypeScript frontend source
│   ├── package.json          # Node dependencies and scripts
│   └── Dockerfile            # Container build spec for web
├── endpoint-agent/           # Cross-platform desktop endpoint agent
│   ├── agent.py              # Core agent runtime loop
│   ├── cli.py                # Command-line entrypoint & argument parser
│   ├── build_windows_exe.py  # PyInstaller single-file compiler
│   └── build_macos_pkg.py    # Native Apple Flat Package compiler
├── android-agent/            # Native Kotlin Android endpoint agent
│   ├── app/                  # Android application module
│   ├── gradlew / gradlew.bat # Gradle wrapper build scripts
│   └── build.gradle.kts      # Android SDK 34-36 build configuration
├── agent/                    # Lightweight passive network discovery daemon
└── README.md / PRD.MD / TRD.MD / SETUP.md
```

---

## SECTION C — ENVIRONMENT CONFIGURATION (.env)

The backend server reads all operational configuration and secrets from the root `.env` file via `pydantic-settings`.

### 1. Create `.env` from Template
```bash
# On Windows PowerShell:
Copy-Item .env.example .env

# On Linux or macOS Bash:
cp .env.example .env
```

### 2. Environment Variables Specification

Open `.env` in your preferred editor. Below is the annotated reference:

```ini
# ==============================================================================
# 1. CORE RUNTIME ENVIRONMENT
# ==============================================================================
# Allowed: "local", "dev", "test", "docker", "production"
# In non-dev environments ("docker", "production"), a real JWT_SECRET is mandatory.
APP_ENV=local

# Database connection URL:
# SQLite (default for development):
DATABASE_URL=sqlite:///./drishti.db
# PostgreSQL (production recommended):
# DATABASE_URL=postgresql+psycopg2://drishti_user:SECURE_PASSWORD@127.0.0.1:5432/drishti_db

# ==============================================================================
# 2. AUTHENTICATION & SECRETS
# ==============================================================================
# JWT signing secret (DO NOT leave as "change-me" in production!)
JWT_SECRET=change-me-to-a-secure-random-64-char-string
JWT_ACCESS_MINUTES=15
JWT_REFRESH_DAYS=7

# Allowed CORS origins for the Web UI (comma-separated if multiple)
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# ==============================================================================
# 3. DEMONSTRATION & HACKATHON LAB MODE
# ==============================================================================
# When set to true, enables fast pairing with static demonstration code ABCD-1234
DRISHTI_DEMO_MODE=false

# Auto-seed the organization and user on startup if DB is empty
AUTO_SEED=true

# When false (default), seeds identity only (starts with clean asset map).
# Set to true to populate the "Acme Retail" canned demonstration network.
DEMO_SEED=false

# ==============================================================================
# 4. ARTIFICIAL INTELLIGENCE & REMEDIATION (OPTIONAL)
# ==============================================================================
# Provider selection: "nvidia", "groq", or "anthropic"
AI_PROVIDER=nvidia
NVIDIA_API_KEY=
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
GROQ_API_KEY=
ANTHROPIC_API_KEY=
AI_MODEL=meta/llama-3.3-70b-instruct
AI_MOCK=false

# ==============================================================================
# 5. THREAT INTELLIGENCE & EXTERNAL FEEDS (OPTIONAL)
# ==============================================================================
# Free-tier keys for URL reputation and CVE enrichment:
GOOGLE_SAFE_BROWSING_KEY=
VIRUSTOTAL_KEY=
NVD_API_KEY=
VULNERS_KEY=

# Telegram Alert Bot (Optional push notifications on critical security events)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# ==============================================================================
# 6. ENDPOINT AGENT INGESTION TUNING
# ==============================================================================
DRISHTI_SERVER_URL=http://localhost:8000
DRISHTI_AGENT_TOKEN=agent-demo-token
```

> [!CAUTION]
> **Production Security Rule**: Never commit `.env` files containing live API keys or production database credentials to version control. The `.gitignore` file is configured to exclude `.env`.

---

## SECTION D — BACKEND SETUP (FASTAPI SERVER)

The backend controller hosts the REST APIs, pairing coordinators, threat detection engines, risk pricers, and relational persistence.

### Option 1: Native Installation

#### Windows (PowerShell)
```powershell
# 1. Navigate to the server directory
cd d:\Drishti-Innofusion\server

# 2. Create isolated Python virtual environment
python -m venv venv

# 3. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 4. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 5. Start the FastAPI server on port 8000 (binds to all interfaces for LAN access)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Linux & macOS (Bash)
```bash
# 1. Navigate to the server directory
cd /path/to/Drishti-Innofusion/server

# 2. Create isolated Python virtual environment
python3.11 -m venv venv

# 3. Activate virtual environment
source venv/bin/activate

# 4. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 5. Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

### Option 2: Docker / Containerized Deployment

Drishti includes production-ready Docker specifications:

```bash
# From the repository root:
docker compose up -d --build
```
This boots:
- `drishti-server` on port `8000` (FastAPI + SQLite volume mount)
- `drishti-web` on port `5173` (Vite SPA with upstream API reverse proxy)

---

### Verifying Backend Health

Verify the server is running by querying the health probe from any browser or terminal:
```bash
curl http://127.0.0.1:8000/health
```
**Expected Response:**
```json
{"status":"ok","version":"0.1.0"}
```

Access the interactive OpenAPI Swagger documentation at:  
👉 **`http://127.0.0.1:8000/docs`**

---

## SECTION E — FRONTEND SETUP (REACT/VITE CONSOLE)

The web console provides the unified dark-mode SOC dashboard, Live Watch monitoring grid, interactive attack graph, and remediation generators.

### 1. Install Dependencies
```bash
# From workspace root:
cd web

# Install exact dependencies via npm
npm install
```

### 2. Configure API Endpoint (If Running on a Different Host)
By default, `web/vite.config.ts` proxies `/api` requests to `http://127.0.0.1:8000`. If your backend runs on a remote server, specify the address via the `VITE_API_URL` environment variable:
```bash
# Example for remote server:
# Windows PowerShell:
$env:VITE_API_URL="http://192.168.1.100:8000"

# Linux / macOS:
export VITE_API_URL="http://192.168.1.100:8000"
```

### 3. Launch Development Server
```bash
npm run dev -- --host 0.0.0.0 --port 5173
```
Open your browser to: **`http://localhost:5173`**

### 4. Build Production Bundle (Optional Verification)
```bash
npm run build
```
This executes `tsc -b && vite build` and outputs optimized assets into `web/dist/`.

---

### 5. Frontend-Only Vercel Demo Mode (No Backend Required)

For online evaluation, presentation, and cloud preview deployments (e.g. on [Vercel](https://vercel.com)), Drishti provides a **Frontend-Only Demo Mode**.

> [!NOTE]
> **Architecture & Scope Distinction:**
> - **Vercel Deployment**: A standalone frontend presentation and evaluation sandbox running entirely in the browser. It uses deterministic synthetic data and requires **ZERO backend services** (no FastAPI server, no SQLite/PostgreSQL database, no live packet capture, no endpoint agents).
> - **Real Security Platform**: Full live network scanning, Nmap integration, cross-platform telemetry streaming, Yen's shortest path calculations, and agent pairing require the local/full-stack environment documented in Sections D, F, G, and I.
> - **Demo Credentials**:
>   - **Email**: `analyst@acme-retail.dev`
>   - **Password**: `drishti-demo`
> - **All telemetry and findings in this mode are strictly labeled** with `[SIMULATED LAB // DEMO MODE]`, `[SYNTHETIC DEMO FINDING]`, and `[SIMULATED INFERENCE]`.

#### Deploying to Vercel:
1. Import the repository into your Vercel dashboard.
2. In **Environment Variables**, set:
   ```text
   VITE_DEMO_MODE=true
   ```
3. The included `vercel.json` automatically configures:
   - **Build Command**: `npm run build --prefix web`
   - **Output Directory**: `web/dist`
   - **Install Command**: `npm install --prefix web`
   - **SPA Rewrites**: Wildcard route handling mapped to `/index.html`
4. The deployment will boot into the standalone demo console without any backend connectivity errors, CORS issues, or broken pages.

---

## SECTION F — WINDOWS ENDPOINT SETUP (AGENT .EXE)

This section explains how to enroll an authorized remote Windows workstation into Drishti monitoring.

> [!IMPORTANT]
> **Distinction of Roles**:
> - **SERVER MACHINE**: The computer running the FastAPI backend (`http://BACKEND_IP:8000`).
> - **TARGET ENDPOINT MACHINE**: The remote Windows PC being monitored.

---

### 1. Prerequisites on Windows Target PC
- Windows 10/11 (64-bit).
- Network reachability to the Drishti server machine via IP and TCP port `8000`.
- Standard user privileges (Admin required only if querying elevated Windows Service configurations).

---

### 2. Obtain the Pre-Compiled Executable
The repository provides a standalone, single-file compiled binary:
📁 **`d:\Drishti-Innofusion\dist\Drishti-Endpoint-Agent-Windows.exe`** (approx. 9.1 MB)

Copy this `.exe` file to the target Windows computer (e.g. to `C:\Drishti\Drishti-Endpoint-Agent-Windows.exe`).

*(Optional: To recompile from source, see [Section Q — Build Artifacts](#section-q--build-artifacts--verification)).*

---

### 3. Execution & Pairing Workflow

On the **TARGET ENDPOINT MACHINE**, open PowerShell or Command Prompt:

```powershell
# Navigate to the folder containing the binary:
cd C:\Drishti

# Execute agent pointing to the Drishti Server:
.\Drishti-Endpoint-Agent-Windows.exe --server http://BACKEND_IP:8000
```
*(Replace `BACKEND_IP` with the actual LAN IP of your Drishti Server, e.g., `http://192.168.1.50:8000`).*

#### Console Output Observed on Target Machine:
```text
[Drishti Agent] Initializing hardware & platform adapter...
[Drishti Agent] Target Server: http://192.168.1.50:8000
[Drishti Agent] Device Hostname: WIN-WORKSTATION-01
[Drishti Agent] State Storage: C:\Users\operator\.drishti\agent
[Drishti Agent] No existing session found. Initiating pairing...
======================================================================
  DRISHTI ENDPOINT PAIRING CODE:   AB7X-92KF
======================================================================
[Drishti Agent] Enter this code in the Drishti SOC Dashboard under:
[Drishti Agent] Live Watch -> Pair Endpoint
[Drishti Agent] Waiting for operator authorization (polling every 3s)...
```

---

### 4. Authorize Agent in Drishti SOC Console
1. On your **Controller Machine**, open the browser to `http://localhost:5173`.
2. Navigate to **Live Watch** in the sidebar.
3. Click the **"Pair Endpoint"** button in the upper toolbar.
4. Enter the 8-character code displayed in the agent console (`AB7X-92KF`).
5. Click **"Authorize Agent"**.

#### Immediate Result:
- The backend verifies the cryptographic hash, provisions an encrypted bearer token (`agent_token`), and registers the agent.
- The target console transitions:
  ```text
  [Drishti Agent] Pairing successful! Bearer token acquired.
  [Drishti Agent] Entering telemetry dispatch loop (interval: 45s).
  [Drishti Agent] Telemetry batch dispatched (20 processes, 48 software items, 8 ports).
  ```
- The device appears in the **Live Watch Grid** with an `ONLINE` badge.

---

### 5. Windows Agent Command-Line Flags Reference

| CLI Flag | Default Value | Description |
|---|---|---|
| `--server <URL>` | `http://localhost:8000` | Full HTTP/HTTPS base URL of the Drishti Server. |
| `--state-dir <PATH>` | `~/.drishti/agent` | Local folder storing device identity (`identity.json`) and token (`credentials.json`). |
| `--heartbeat-interval <SEC>` | `45.0` | Heartbeat pulse interval in seconds. |
| `--force-pair` | `false` | **Crucial Troubleshooting Flag**: Purges cached credentials and forces generation of a new pairing code. |
| `-v` / `--verbose` | `false` | Enables verbose debug logging showing raw collector timing and JSON payload size. |

---

## SECTION G — macOS ENDPOINT SETUP (AGENT .PKG)

This section details enrolling an authorized Apple macOS workstation into Drishti.

### 1. Prerequisites on macOS Target
- macOS 12 (Monterey), macOS 13 (Ventura), or macOS 14 (Sonoma).
- Architecture: Apple Silicon (ARM64) or Intel (x86_64).
- Terminal access with standard user or administrator rights.

---

### 2. Obtain & Install the Agent Package
The standalone installer package is located at:
📁 **`dist/Drishti-Endpoint-Agent-macOS.pkg`**

#### Installation via GUI:
Double-click `Drishti-Endpoint-Agent-macOS.pkg` and follow the standard macOS Installer prompts.

#### Installation via Terminal:
```bash
sudo installer -pkg dist/Drishti-Endpoint-Agent-macOS.pkg -target /
```
This deploys the agent files into `/opt/drishti/agent/` and configures a launchd daemon template.

---

### 3. Launching & Pairing the macOS Agent
From Terminal on the target Mac:
```bash
/opt/drishti/agent/bin/drishti-agent --server http://BACKEND_IP:8000
```
1. Note the pairing code (e.g. `K92M-LP44`).
2. Enter the code in the Drishti SOC Dashboard under **Live Watch → Pair Endpoint**.
3. Telemetry streams every 45 seconds.

---

### 4. macOS Privacy Permissions & Truthful Platform Boundaries

macOS enforces strict Transparency, Consent, and Control (TCC) boundaries. Drishti respects native OS security controls:

| Telemetry Item | macOS Native Behavior | Drishti Truthful Degradation |
|---|---|---|
| **CPU, Load, Cores** | Allowed via `sysctl` / `libproc`. | Fully reported in telemetry. |
| **System RAM / Disk** | Allowed via `vm_stat` and `statfs`. | Fully reported in telemetry. |
| **Process Tree** | Unprivileged processes can observe own and standard system PIDs via `sysctl`. | Reported up to POSIX permission boundaries. |
| **Network Connections** | Readily accessible via `netstat` / `getifaddrs`. | Reported in telemetry. |
| **Safari / Chrome Tabs & History** | **BLOCKED by macOS TCC sandbox**. Cross-app SQLite databases in `~/Library/Application Support/` require Full Disk Access. | **Drishti NEVER bypasses TCC**. Browser tab URLs are transparently omitted; installed browser binaries are inventoried from `/Applications`. |

---

## SECTION H — LINUX ENDPOINT SUPPORT STATUS

> [!IMPORTANT]
> **Definitive Status Notice**:  
> **Linux native endpoint agent packaging (`.deb`, `.rpm`, or systemd installer) is currently NOT IMPLEMENTED.**

### Current Codebase Reality:
1. The backend server and web console run natively on Linux (Ubuntu/Debian/RHEL).
2. The network discovery scanner (`agent/drishti_watch.py`) runs on Linux to passively identify LAN hosts via ARP, DNS, and mDNS.
3. However, a dedicated single-binary packaged daemon for Linux desktop telemetry is marked as **`[PLANNED]`**.
4. Operators should not attempt to execute non-existent Linux `.deb` or `.rpm` packages.

---

## SECTION I — ANDROID ENDPOINT SETUP (APK)

Drishti provides a dedicated, native Kotlin Android endpoint agent compatible with Android 14+ (API 34 and API 35).

---

### 1. Android Prerequisites
- Physical Android phone/tablet running Android 14+ or an Android Virtual Device (AVD) running Google APIs System Image API 34/35.
- USB Debugging enabled on physical device (**Settings → Developer options → USB debugging**).
- Computer with `adb` installed.

---

### 2. APK Location
The verified pre-compiled debug APK is located at:
📁 **`d:\Drishti-Innofusion\dist\Drishti-Android-Agent-debug.apk`** (approx. 17.3 MB)

---

### 3. Installation Procedure

Connect the target Android device via USB and verify ADB connection:
```bash
adb devices
```
*(Ensure device status shows `device`, not `unauthorized`).*

#### Install APK via ADB:
```bash
adb install -r d:\Drishti-Innofusion\dist\Drishti-Android-Agent-debug.apk
```
**Expected Output:**
```text
Performing Streamed Install
Success
```

Verify package presence:
```bash
adb shell pm list packages | grep drishti
# Output: package:com.drishti.agent
```

---

### 4. Permission Grants

#### A. Foreground Application Tracking Permission (`PACKAGE_USAGE_STATS`)
Android strictly protects application usage data. To allow the agent's `ForegroundAppCollector` to observe the currently active app package name, grant Usage Access:

**Via ADB (Fastest for Hackathon / Lab)**:
```bash
adb shell appops set com.drishti.agent PACKAGE_USAGE_STATS allow
```

**Via Android Settings GUI**:
1. Open **Settings → Apps → Special app access**.
2. Tap **Usage access**.
3. Locate **Drishti Agent** and toggle the switch to **Allow usage tracking**.

#### B. Defensive Network Shield Consent (`BIND_VPN_SERVICE`)
To capture outbound network flow metadata (destination IPs, destination ports, protocols, and DNS queries), the app includes `DrishtiVpnService`.
1. Inside the Drishti Android App, tap **"Enable Network Shield"**.
2. Android displays the standard modal: *"Drishti Agent wants to set up a VPN connection that allows it to monitor network traffic"*.
3. Tap **OK / Accept**.

---

### 5. Pairing the Android Device to the SOC

#### Demonstration Pairing Mode (`ABCD-1234`)
1. Ensure the Drishti backend server is started with `DRISHTI_DEMO_MODE=true` (or set in `.env`).
2. Open the **Drishti Agent** app on Android.
3. In the **Server URL** input field, specify your server's reachable IP:
   - For Android Emulator: `http://10.0.2.2:8000`
   - For Physical Device on Wi-Fi: `http://192.168.x.x:8000`
4. Toggle **"Demo Mode Pairing"** ON.
5. Tap **"Start Pairing"**. The screen will display the static demo code: **`ABCD-1234`**.
6. On the Web SOC Dashboard, open **Live Watch → Pair Endpoint**, input `ABCD-1234`, and click **Authorize**.
7. The Android agent transitions to `CONNECTED` status.

---

### 6. Android Platform Sandbox Boundaries & Truthful Telemetry

Android's Linux kernel and SELinux policies enforce rigid process isolation. Drishti operates strictly within permitted Android APIs:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    ANDROID OS PRIVACY & SANDBOX BOUNDARY                │
├──────────────────────────────────────┬──────────────────────────────────┤
│ ✅ WHAT DRISHTI LEGITIMATELY COLLECTS │ ❌ WHAT IS STRICTLY IMPOSSIBLE   │
├──────────────────────────────────────┼──────────────────────────────────┤
│ • Device Model, Board, Bootloader    │ • Reading other apps' private    │
│ • Android Version & Security Patch   │   files or SQLite databases      │
│ • CPU Core Count & Clock Frequencies │ • Global /proc/stat CPU load     │
│ • PowerManager Thermal Status Code   │ • Cross-app Chrome tab URLs or   │
│ • Total / Available RAM & Internal Storage  incognito browsing history │
│ • Battery % & Charging Health        │ • Reading global /proc/net/tcp   │
│ • Wi-Fi SSID, Link Speed & Gateway   │ • Intercepting TLS encrypted app │
│ • Installed App Inventory & Permissions     payloads without root CA    │
│ • Foreground App Name (via UsageStats)                                  │
│ • 5-Tuple Network Flows (via VpnService)                                │
│ • Cryptographic Token in HW Keystore                                    │
└──────────────────────────────────────┴──────────────────────────────────┘
```

---

## SECTION J — TARGET DEVICE SETUP MATRIX

| Target Device | Setup Method | Agent / Software | Pairing Method | Available Telemetry | Known Platform Limitations |
|---|---|---|---|---|---|
| **Windows 10/11 PC** | Standalone Single-File Executable | `Drishti-Endpoint-Agent-Windows.exe` | Dynamic 8-char code (e.g. `AB7X-92KF`) via Dashboard | Full CPU%, RAM, top 20 processes, installed software, listening ports, active TCP/UDP connections, Windows services | Requires Administrator for elevated system services; no raw browser URL snooping |
| **macOS (Intel / M-Series)** | Native Flat Package Installer | `Drishti-Endpoint-Agent-macOS.pkg` | Dynamic 8-char code via Dashboard | System load, RAM, disk, process list, network interfaces | TCC blocks cross-app browser history/tab URLs; requires Full Disk Access for deep logs |
| **Linux Workstation / Server** | Python discovery daemon | `agent/drishti_watch.py` | Pre-shared token (`--token`) | Passive ARP/DNS/mDNS discovery, open port scanning | **Native packaged agent (`.deb`/`.rpm`) is PLANNED** |
| **Android 14/15 Device** | Native Android APK via ADB | `Drishti-Android-Agent-debug.apk` | Dynamic code or Demo Mode (`ABCD-1234`) | Device specs, thermal status, RAM, storage, battery, installed packages, foreground app, 5-tuple VPN flows | Restricted `/proc/stat`, no raw browser tabs, hardware MAC randomized by OS |

---

## SECTION K — NETWORK & ROUTING CONFIGURATION

To enable endpoint agents to report telemetry to the Drishti server, ensure proper Layer 3 IP routing and Layer 4 TCP reachability.

```text
┌─────────────────────────────────┐           ┌─────────────────────────────────┐
│       DRISHTI SERVER HOST       │           │     TARGET ENDPOINT HOST        │
│  IP: BACKEND_IP (192.168.1.50)  │           │  IP: ENDPOINT_IP (192.168.1.120)│
│  FastAPI Port: 8000 (INBOUND)   │ ◄───────  │  Agent Process / App            │
│  Web Console: 5173              │   HTTP    │  Outbound TCP to Port 8000      │
└─────────────────────────────────┘           └─────────────────────────────────┘
```

### Network Connectivity Verification Commands

Execute these commands to confirm network reachability:

#### Step 1: Find Server IP
- **On Server (Windows PowerShell)**:
  ```powershell
  Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object IPAddress, InterfaceAlias
  ```
- **On Server (Linux/macOS)**:
  ```bash
  ip -4 addr show || ifconfig
  ```
*Assume the resulting IP is `192.168.1.50` (`BACKEND_IP`).*

#### Step 2: Test Reachability from Endpoint Machine
- **From Windows Endpoint (PowerShell)**:
  ```powershell
  # Test ICMP Ping
  Test-Connection -ComputerName BACKEND_IP -Count 2

  # Test TCP Port 8000 Connectivity
  Test-NetConnection -ComputerName BACKEND_IP -Port 8000
  ```
  *Ensure `TcpTestSucceeded : True` is returned.*

- **From Linux/macOS Endpoint (Terminal)**:
  ```bash
  nc -zv BACKEND_IP 8000
  # Expected: Connection to BACKEND_IP port 8000 [tcp/*] succeeded!
  ```

- **From Android Endpoint (via ADB Shell)**:
  ```bash
  adb shell ping -c 2 BACKEND_IP
  ```

---

## SECTION L — FIREWALL CONFIGURATION RULES

If endpoint agents cannot reach `http://BACKEND_IP:8000`, the host firewall on the **SERVER MACHINE** is almost always blocking inbound connections.

> [!WARNING]
> Do NOT expose port 8000 to the public Internet without a reverse proxy, TLS encryption, and authentication hardening. Open port 8000 strictly on your private local subnet (LAN).

### 1. Windows Server / Host Firewall Rule
Execute in **PowerShell as Administrator** on the **SERVER MACHINE**:

```powershell
# Open inbound TCP port 8000 for Drishti Server:
New-NetFirewallRule -DisplayName "Drishti Backend API (Port 8000)" `
                    -Direction Inbound `
                    -LocalPort 8000 `
                    -Protocol TCP `
                    -Action Allow `
                    -Profile Private,Domain
```

To verify the rule is active:
```powershell
Get-NetFirewallRule -DisplayName "*Drishti*" | Select-Object Name, Enabled, Direction, Action
```

---

### 2. Linux (UFW / Iptables) Firewall Rule
Execute on the **Linux Server Machine**:

```bash
# Allow inbound port 8000 from local subnet (e.g. 192.168.1.0/24):
sudo ufw allow from 192.168.1.0/24 to any port 8000 proto tcp comment "Drishti API"
sudo ufw status verbose
```

---

### 3. macOS Application Firewall
1. Open **System Settings → Network → Firewall**.
2. If the firewall is ON, click **Options**.
3. Ensure Python / Uvicorn is listed as **"Allow incoming connections"**.

---

## SECTION M — PAIRING & AUTHENTICATION MECHANICS

Drishti implements a robust, short-lived cryptographic pairing exchange to prevent unauthorized agents from injecting telemetry into an organization.

### The Cryptographic Protocol

```mermaid
%%{init: {'theme': 'dark'}}%%
sequenceDiagram
    autonumber
    actor Operator as SOC Analyst (Browser)
    participant Server as Drishti Backend (Port 8000)
    participant Agent as Endpoint Agent (Target PC/Phone)

    Agent->>Server: POST /api/endpoint/pairing/init<br/>{hostname, os, mac, current_ip}
    Server-->>Agent: {session_id, pairing_code: "AB7X-92KF", expires_at}
    Note over Agent: Displays "AB7X-92KF" on terminal / mobile UI

    loop Poll Status Every 3s
        Agent->>Server: POST /api/endpoint/pairing/status<br/>{session_id, agent_id}
        Server-->>Agent: {status: "WAITING_FOR_PAIR"}
    end

    Operator->>Server: POST /api/endpoint/pairing/pair<br/>{pairing_code: "AB7X-92KF"}
    Note over Server: Matches SHA-256(code), verifies expiry (5 min),<br/>generates raw 32-byte agent_token,<br/>stores hash in DB, marks PAIRED

    Agent->>Server: POST /api/endpoint/pairing/status
    Server-->>Agent: {status: "PAIRED", agent_token: "32-byte-hex-secret"}
    Note over Server: Clears agent_token from DB session (One-time release)
    Note over Agent: Stores agent_token securely in credentials.json / Keystore

    loop Telemetry Pulse (Every 45s)
        Agent->>Server: POST /api/endpoint/telemetry (Bearer Token)
        Server-->>Agent: {success: true, accepted_at}
    end
```

### Detailed Pairing Mechanics
1. **Alphabet & Entropy**: Codes are drawn from the unambiguous alphabet `23456789ABCDEFGHJKLMNPQRSTUVWXYZ` (omitting visual lookalikes `0`, `O`, `1`, `I`, `L`).
2. **TTL**: Standard pairing codes expire in **5 minutes**.
3. **One-Time Release**: Once consumed, the raw secret token is purged from the session table and stored only as a cryptographic hash (`hash_agent_token`).
4. **Force-Pairing**: If the agent's stored credentials become stale or desynchronized:
   - On Windows: Run `.\Drishti-Endpoint-Agent-Windows.exe --force-pair`
   - On Android: Clear App Data or toggle Demo Mode.

---

## SECTION N — RUNNING AN END-TO-END VERIFICATION DEMO

Follow this complete workflow to demonstrate Drishti in an authorized laboratory or hackathon environment:

### Step 1: Boot Backend
```powershell
# In server directory:
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
*Console confirms database schema bootstrap and scheduler startup.*

### Step 2: Boot Web SOC Console
```powershell
# In web directory:
npm run dev
```
*Access `http://localhost:5173` and log in with default credentials (`admin@acme.corp` / password).*

### Step 3: Launch Windows Endpoint Agent
```powershell
# On Windows Endpoint PC:
.\Drishti-Endpoint-Agent-Windows.exe --server http://BACKEND_IP:8000 --verbose
```
*Copy the 8-character pairing code.*

### Step 4: Authorize in Web SOC Console
1. Navigate to **Live Watch**.
2. Click **Pair Endpoint** → paste the code → click **Authorize**.
3. Observe the workstation node light up in the **Live Watch Grid** with an `ONLINE` badge.

### Step 5: Verify Live Telemetry Stream
Click on the newly registered workstation card in **Live Watch**:
- Expand the **Detail Drawer**.
- Confirm CPU usage graph is live.
- Confirm RAM utilization bar reflects actual workstation memory.
- Review the **Top 20 Processes** table (verify PID, executable, and memory RSS).
- Review **Listening Ports** and **Active Connections**.

### Step 6: Launch Android Endpoint & Network Shield
1. Install `Drishti-Android-Agent-debug.apk` on an Android 14+ device.
2. Launch app → configure `http://BACKEND_IP:8000` → pair device.
3. Tap **"Enable Network Shield"** → accept VPN dialog.
4. On the Web SOC, click the Android device card:
   - Verify hardware specs, battery %, and thermal status.
   - Switch foreground apps on phone (e.g. open Chrome or Settings) → verify **Foreground App** updates in near real-time.
   - Generate network traffic → observe outbound flow records in the **Network Flows** tab.

### Step 7: Inspect Threat Detection & Attack Paths
1. Navigate to **Attack Paths** in the web sidebar.
2. Observe Yen's algorithm calculating candidate lateral movement paths from edge assets to crown jewels.
3. Review dollar-denominated risk valuations.
4. Open **Remediation** to inspect auto-generated Ansible and firewall mitigation playbooks.

---

## SECTION O — COMPREHENSIVE TROUBLESHOOTING MATRIX

| Category | Observed Symptom | Probable Cause | Verification Step | Definitive Remediation |
|---|---|---|---|---|
| **Connectivity** | Agent outputs `ConnectionRefusedError` or `Failed to connect to server` | Backend is not running or listening only on `127.0.0.1` | Run `netstat -ano \| findstr 8000` on server | Start backend binding to all interfaces: `uvicorn app.main:app --host 0.0.0.0 --port 8000` |
| **Firewall** | `Test-NetConnection -Port 8000` times out from remote endpoint | Server firewall is blocking inbound port 8000 | Check Windows Defender Firewall or `ufw status` | Add inbound firewall rule allowing TCP 8000 (see Section L) |
| **Pairing** | Dashboard reports `"Invalid pairing code"` | Code was entered with typos, has expired (5 min TTL), or agent is sending stale token | Check agent terminal log for code match | Restart agent with `--force-pair` flag to purge credentials and generate a fresh code |
| **Android Pairing** | Android Demo Mode code `ABCD-1234` is rejected | Backend server is running without `DRISHTI_DEMO_MODE=true` | Check backend `.env` file | Add `DRISHTI_DEMO_MODE=true` to `.env` and restart FastAPI |
| **Android Data** | Foreground app displays `null` or `PERMISSION_REQUIRED` | `PACKAGE_USAGE_STATS` special access has not been granted | Run `adb shell dumpsys usagestats` | Grant permission via ADB: `adb shell appops set com.drishti.agent PACKAGE_USAGE_STATS allow` |
| **Android VPN** | Network flows table is empty | Defensive VPN shield is disabled or consent dialog was rejected | Check Android notification bar for VPN key icon | Open Drishti Android App, tap "Enable Network Shield", and accept OS VPN dialog |
| **Windows Agent** | `psutil` or `winreg` import errors when running from source | Python environment is missing required dependencies | Run `pip list` in active venv | Run `pip install -r endpoint-agent/requirements.txt` |
| **Web Console** | Web page loads blank or shows `NetworkError` on API calls | Vite dev server cannot reach backend proxy | Inspect browser developer tools (F12) Network tab | Verify backend is alive at `http://localhost:8000/health` and `VITE_API_URL` is correct |
| **Database** | Backend crashes with `OperationalError: no such column` | Stale dev database schema from older version | Inspect `drishti.db` schema | Restart server (`app.db_init.reconcile_columns` auto-reconciles additive columns) or backup and delete `drishti.db` to re-seed |

---

## SECTION P — SECURITY, PRIVACY & CONSENT BOUNDARIES

> [!CAUTION]
> **Strict Operational Mandate**: Drishti is a strictly defensive cybersecurity platform intended solely for authorized environments (corporate internal networks, cyber ranges, security labs, and managed enterprise device fleets). Unauthorized deployment on devices without explicit owner consent is prohibited.

### 1. Transparency & Least Privilege
- **No Covert Surveillance**: Drishti endpoint agents do NOT function as spyware or stealth rootkits. The agents run as visible processes, log actions openly, and require user consent for mobile network observation.
- **No Keystroke Logging or Audio/Video Recording**: Drishti contains zero modules for keylogging, screen recording, microphone capture, or camera access.
- **No Cross-App Content Snooping**: The agent does not read private messages, personal photos, or browser cookies. Browser observation is restricted to identifying installed browser binaries and active tab URLs strictly via the explicit opt-in Chrome Guard extension.

### 2. Cryptographic Token Protection
- Endpoint bearer tokens are generated using cryptographically strong pseudo-random number generators (`secrets.token_hex(32)`).
- Tokens are stored using platform-native security:
  - **Android**: Hardware-backed Android Keystore (`EncryptedSharedPreferences`).
  - **Desktop**: Isolated state directory with restricted file system permissions.
- In-transit communication utilizes TLS/HTTPS.

---

## SECTION Q — BUILD ARTIFACTS & VERIFICATION

Drishti includes automated compilers to produce self-contained distributables.

### 1. Windows Executable (`.exe`) Compilation
The Windows compiler script builds an isolated virtual environment, installs PyInstaller, and bundles all collector modules:

```powershell
# From workspace root on a Windows build host:
python endpoint-agent\build_windows_exe.py
```
- **Output Artifact**: `dist\Drishti-Endpoint-Agent-Windows.exe`
- **Verification**: Run `Get-FileHash dist\Drishti-Endpoint-Agent-Windows.exe -Algorithm SHA256` to record the build integrity hash.

### 2. Android APK (`.apk`) Compilation
The Android build uses Gradle wrapper with Kotlin 1.9+ and Android Gradle Plugin:

```powershell
# From workspace root:
cd android-agent
.\gradlew.bat assembleDebug
```
- **Output Artifact**: `android-agent\app\build\outputs\apk\debug\app-debug.apk`
- The script automatically copies the binary to: `dist\Drishti-Android-Agent-debug.apk`.

### 3. macOS Package (`.pkg`) Compilation
The macOS builder synthesizes a standard Apple Flat Package (XAR archive containing payload and scripts):

```bash
python3 endpoint-agent/build_macos_pkg.py
```
- **Output Artifact**: `dist/Drishti-Endpoint-Agent-macOS.pkg`

---

## SECTION R — ARCHITECTURE & FLOW DIAGRAMS

### 1. End-to-End System Topology
```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TB
    subgraph FLEET ["Managed Endpoint Fleet"]
        WIN["💻 Windows Workstation<br/>Drishti-Endpoint-Agent.exe"]
        MAC["🍏 macOS Workstation<br/>Drishti-Endpoint-Agent.pkg"]
        AND["📱 Android Mobile Device<br/>Drishti-Android-Agent.apk"]
    end

    subgraph NETWORK_PLANE ["Local Network Monitoring"]
        ZEEK["🔬 Zeek / TShark / Scapy<br/>Packet Capture Adapter"]
        NET_SCAN["👁️ drishti_watch.py<br/>Passive ARP/mDNS Discovery"]
    end

    subgraph SERVER_CORE ["Drishti Core Controller (Port 8000)"]
        INGEST["📡 Telemetry & Pairing Router<br/>/api/endpoint/*"]
        DETECT["⚡ Traffic Detection Engine<br/>DoS · PortScan · Infiltration"]
        GRAPH["🕸️ NetworkGraphEngine<br/>Topology & Choke Points"]
        YEN["🎯 Attack Path Pricer<br/>Yen's K-Shortest Paths"]
        DB[(🗄️ Relational Persistence<br/>SQLite / PostgreSQL)]
    end

    subgraph SOC_UI ["Analyst Interface (Port 5173)"]
        WEB["🌐 Dark-Mode SOC Console<br/>Live Watch · Grid · ReactFlow Graph"]
    end

    WIN -->|HTTP/JSON :8000| INGEST
    MAC -->|HTTP/JSON :8000| INGEST
    AND -->|HTTP/JSON :8000| INGEST
    ZEEK -->|Raw Flow Records| DETECT
    NET_SCAN -->|Discovered Hosts| INGEST

    INGEST --> DB
    INGEST --> DETECT
    DETECT --> GRAPH
    GRAPH --> YEN
    YEN --> DB

    WEB <-->|REST + Polling| INGEST
    WEB <-->|Query State| DB
```

---

## SECTION S — EXTERNAL REFERENCE INTEGRATION (GITHUB ARCHIVE)

When reviewing external architectural blueprints or reference repositories (such as GitHub Archify archives):

1. **Analytical Reference Only**: External material serves as a reference framework for documentation standards and design patterns.
2. **Preserve Drishti Architecture**: Do not import unrelated dependencies, alien module names, or external mock structures. Drishti's verified source code remains the authoritative source of truth.
3. **Traceability**: All architectural models documented in `PRD.MD`, `TRD.MD`, and `SETUP.md` correspond strictly to active endpoints, classes, and UI components in this codebase.

---

## SECTION T — FINAL DOCUMENTATION AUDIT

| Documentation Component | Verification Status | Source Code Validation Anchor |
|---|---|---|
| **Prerequisites & Tools** | ✅ VERIFIED | Checked against `server/requirements.txt`, `web/package.json`, and `android-agent/build.gradle.kts`. |
| **AI Agent Auto-Setup** | ✅ VERIFIED | Validated `setup.ps1` (Windows), `setup.sh` (Linux/macOS), and `start-mac.sh`. |
| **Backend Ports & Routes** | ✅ VERIFIED | Verified `server/app/main.py` (Port 8000) and `server/app/api/endpoint.py`. |
| **Windows Executable CLI** | ✅ VERIFIED | Verified against `endpoint-agent/cli.py` (`--server`, `--force-pair`, `--heartbeat-interval`). |
| **Android SDK & Permissions** | ✅ VERIFIED | Verified against `android-agent/app/src/main/AndroidManifest.xml` (API 34/35). |
| **Pairing Codes & Hashes** | ✅ VERIFIED | Verified against `server/app/api/endpoint.py` (`generate_pairing_code`, `DEMO_PAIRING_CODE = "ABCD-1234"`). |
| **Database Schema** | ✅ VERIFIED | Verified `server/app/models/endpoint.py` and `server/app/db_init.py`. |
