<#
.SYNOPSIS
    Drishti Cybersecurity Platform — Automated Windows Setup Script
.DESCRIPTION
    Autonomous setup script for AI Agents and Human Operators.
    Detects the operating system, verifies/installs prerequisites (Python 3.11+, Node.js 18+, Git),
    initializes the .env environment, configures the backend venv, installs web dependencies,
    and validates the complete stack.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup.ps1
#>

[CmdletBinding()]
param(
    [switch]$SkipPrereqInstall = $false,
    [switch]$DemoMode = $true
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   DRISHTI CYBERSECURITY PLATFORM - AUTOMATED WINDOWS SETUP          " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

$WorkspaceRoot = $PSScriptRoot
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Get-Location).Path
}

Write-Host "Workspace Root: $WorkspaceRoot" -ForegroundColor Gray

# -----------------------------------------------------------------------------
# 1. OS & Architecture Detection
# -----------------------------------------------------------------------------
Write-Host "`n[Step 1/6] Detecting Operating System and Architecture..." -ForegroundColor Yellow
$OSInfo = Get-CimInstance Win32_OperatingSystem
$Arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
Write-Host "  [+] OS: $($OSInfo.Caption) ($($OSInfo.Version)) - Arch: $Arch" -ForegroundColor Green

# -----------------------------------------------------------------------------
# 2. Prerequisites Check & Automated Remediation
# -----------------------------------------------------------------------------
Write-Host "`n[Step 2/6] Checking Prerequisites (Python, Node.js, Git)..." -ForegroundColor Yellow

function Test-CommandAvailable {
    param([string]$CommandName)
    $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue
    return ($null -ne $cmd)
}

# Python Check
$PythonCmd = $null
if (Test-CommandAvailable "python") {
    $pyVer = (python --version 2>&1)
    Write-Host "  [+] Python detected: $pyVer" -ForegroundColor Green
    $PythonCmd = "python"
} elseif (Test-CommandAvailable "py") {
    $pyVer = (py -3 --version 2>&1)
    Write-Host "  [+] Python Launcher detected: $pyVer" -ForegroundColor Green
    $PythonCmd = "py -3"
} else {
    Write-Host "  [!] Python is NOT installed or not in PATH." -ForegroundColor Yellow
    if (-not $SkipPrereqInstall -and (Test-CommandAvailable "winget")) {
        Write-Host "  [*] Attempting automatic Python 3.11 installation via winget..." -ForegroundColor Cyan
        try {
            winget install --id Python.Python.3.11 -e --silent --accept-package-agreements --accept-source-agreements
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            if (Test-CommandAvailable "python") {
                $PythonCmd = "python"
                Write-Host "  [+] Python installed successfully!" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [-] Failed to auto-install Python via winget. Please install Python 3.11+ manually." -ForegroundColor Red
        }
    } else {
        Write-Host "  [-] Please install Python 3.11+ manually or run: winget install Python.Python.3.11" -ForegroundColor Red
    }
}

# Node.js Check
$NodeCmd = $null
if (Test-CommandAvailable "node") {
    $nodeVer = (node -v 2>&1)
    Write-Host "  [+] Node.js detected: $nodeVer" -ForegroundColor Green
    $NodeCmd = "node"
} else {
    Write-Host "  [!] Node.js is NOT installed or not in PATH." -ForegroundColor Yellow
    if (-not $SkipPrereqInstall -and (Test-CommandAvailable "winget")) {
        Write-Host "  [*] Attempting automatic Node.js LTS installation via winget..." -ForegroundColor Cyan
        try {
            winget install --id OpenJS.NodeJS.LTS -e --silent --accept-package-agreements --accept-source-agreements
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            if (Test-CommandAvailable "node") {
                $NodeCmd = "node"
                Write-Host "  [+] Node.js installed successfully!" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [-] Failed to auto-install Node.js via winget. Please install from https://nodejs.org" -ForegroundColor Red
        }
    } else {
        Write-Host "  [-] Please install Node.js 18+ manually or run: winget install OpenJS.NodeJS.LTS" -ForegroundColor Red
    }
}

# Git Check
if (Test-CommandAvailable "git") {
    $gitVer = (git --version 2>&1)
    Write-Host "  [+] Git detected: $gitVer" -ForegroundColor Green
} else {
    Write-Host "  [!] Git not found in PATH." -ForegroundColor Yellow
    if (-not $SkipPrereqInstall -and (Test-CommandAvailable "winget")) {
        winget install --id Git.Git -e --silent --accept-package-agreements --accept-source-agreements
    }
}

# -----------------------------------------------------------------------------
# 3. Configure .env Environment
# -----------------------------------------------------------------------------
Write-Host "`n[Step 3/6] Setting up Workspace Environment (.env)..." -ForegroundColor Yellow
$EnvPath = Join-Path $WorkspaceRoot ".env"
$EnvExamplePath = Join-Path $WorkspaceRoot ".env.example"

if (-not (Test-Path $EnvPath)) {
    if (Test-Path $EnvExamplePath) {
        Copy-Item -Path $EnvExamplePath -Destination $EnvPath
        Write-Host "  [+] Created .env from .env.example" -ForegroundColor Green
    } else {
        @"
APP_ENV=local
DATABASE_URL=sqlite:///./drishti.db
JWT_SECRET=drishti-local-development-secret-key-32chars
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
DRISHTI_DEMO_MODE=true
AUTO_SEED=true
DEMO_SEED=false
DRISHTI_SERVER_URL=http://localhost:8000
"@ | Out-File -FilePath $EnvPath -Encoding utf8
        Write-Host "  [+] Generated default .env file" -ForegroundColor Green
    }
} else {
    Write-Host "  [+] Existing .env file found." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 4. Python Backend Setup (server/)
# -----------------------------------------------------------------------------
Write-Host "`n[Step 4/6] Bootstrapping FastAPI Server Environment..." -ForegroundColor Yellow
$ServerDir = Join-Path $WorkspaceRoot "server"
$ServerVenvDir = Join-Path $ServerDir "venv"
$ServerPython = Join-Path $ServerVenvDir "Scripts\python.exe"
$ServerPip = Join-Path $ServerVenvDir "Scripts\pip.exe"

if (-not (Test-Path $ServerPython)) {
    Write-Host "  [*] Creating Python virtual environment in server\venv..." -ForegroundColor Cyan
    if ($PythonCmd -eq "py -3") {
        py -3 -m venv $ServerVenvDir
    } else {
        python -m venv $ServerVenvDir
    }
}

if (Test-Path $ServerPip) {
    Write-Host "  [*] Installing server dependencies from requirements.txt..." -ForegroundColor Cyan
    & $ServerPip install --upgrade pip --quiet
    & $ServerPip install -r (Join-Path $ServerDir "requirements.txt") --quiet
    Write-Host "  [+] Backend dependencies successfully installed!" -ForegroundColor Green
} else {
    Write-Host "  [-] Server virtual environment creation failed. Ensure Python 3.11+ is installed." -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 5. Frontend Setup (web/)
# -----------------------------------------------------------------------------
Write-Host "`n[Step 5/6] Bootstrapping Web SOC Console (React + Vite)..." -ForegroundColor Yellow
$WebDir = Join-Path $WorkspaceRoot "web"
$WebPackageJson = Join-Path $WebDir "package.json"

if (Test-Path $WebPackageJson) {
    Write-Host "  [*] Running 'npm install' in web/ directory..." -ForegroundColor Cyan
    Push-Location $WebDir
    try {
        npm install --silent
        Write-Host "  [+] Frontend dependencies successfully installed!" -ForegroundColor Green
    } catch {
        Write-Host "  [-] Failed to install frontend dependencies: $_" -ForegroundColor Red
    } finally {
        Pop-Location
    }
} else {
    Write-Host "  [-] web/package.json not found!" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 6. Endpoint Agent Setup (Windows)
# -----------------------------------------------------------------------------
Write-Host "`n[Step 6/6] Verifying Endpoint Agent and Build Artifacts..." -ForegroundColor Yellow
$ExeDist = Join-Path $WorkspaceRoot "dist\Drishti-Endpoint-Agent-Windows.exe"
if (Test-Path $ExeDist) {
    $fileSizeMB = [math]::Round((Get-Item $ExeDist).Length / 1MB, 2)
    Write-Host "  [+] Standalone Windows Agent executable found: dist\Drishti-Endpoint-Agent-Windows.exe ($fileSizeMB MB)" -ForegroundColor Green
} else {
    Write-Host "  [*] Precompiled agent exe not in dist\. Setting up endpoint-agent Python environment..." -ForegroundColor Gray
    $AgentVenv = Join-Path $WorkspaceRoot "endpoint-agent\venv"
    if (-not (Test-Path $AgentVenv)) {
        python -m venv $AgentVenv
        & (Join-Path $AgentVenv "Scripts\pip.exe") install -r (Join-Path $WorkspaceRoot "endpoint-agent\requirements.txt") --quiet
        Write-Host "  [+] endpoint-agent venv configured." -ForegroundColor Green
    }
}

# -----------------------------------------------------------------------------
# Final Summary & Launch Instructions
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "   DRISHTI SETUP COMPLETE & READY TO RUN!                            " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  To launch the entire platform, open two terminals:" -ForegroundColor White
Write-Host ""
Write-Host "  TERMINAL 1 (FastAPI Server):" -ForegroundColor Cyan
Write-Host "     cd server" -ForegroundColor Gray
Write-Host "     .\venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "     uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload" -ForegroundColor Yellow
Write-Host ""
Write-Host "  TERMINAL 2 (Web SOC Dashboard):" -ForegroundColor Cyan
Write-Host "     cd web" -ForegroundColor Gray
Write-Host "     npm run dev" -ForegroundColor Yellow
Write-Host ""
Write-Host "  TERMINAL 3 (Optional - Windows Endpoint Agent):" -ForegroundColor Cyan
Write-Host "     .\dist\Drishti-Endpoint-Agent-Windows.exe --server http://localhost:8000" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Console URL : http://localhost:5173" -ForegroundColor Green
Write-Host "  API Docs    : http://localhost:8000/docs" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
