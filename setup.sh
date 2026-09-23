#!/usr/bin/env bash
# ==============================================================================
# Drishti Cybersecurity Platform — Automated Linux & macOS Setup Script
# Autonomous installation script for AI Agents and Human Operators
# Usage: chmod +x setup.sh && ./setup.sh
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}═════════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}   🚀 DRISHTI CYBERSECURITY PLATFORM — AUTOMATED UNIX/MAC SETUP     ${NC}"
echo -e "${CYAN}═════════════════════════════════════════════════════════════════════${NC}"
echo ""

# ── 1. OS & Architecture Detection ───────────────────────────────────────────
echo -e "${YELLOW}🔍 [Step 1/6] Detecting Operating System & Distribution...${NC}"
OS_TYPE="$(uname -s)"
ARCH_TYPE="$(uname -m)"

echo -e "  ✓ Kernel: ${OS_TYPE} | Architecture: ${ARCH_TYPE}"

if [ "$OS_TYPE" = "Darwin" ]; then
    OS_NAME="macOS"
    MAC_VER="$(sw_vers -productVersion 2>/dev/null || echo 'Unknown')"
    echo -e "  ✓ Platform: ${OS_NAME} ${MAC_VER}"
elif [ "$OS_TYPE" = "Linux" ]; then
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="${NAME:-Linux}"
        echo -e "  ✓ Distribution: ${OS_NAME} (${VERSION_ID:-Unknown})"
    else
        OS_NAME="Linux (Generic)"
        echo -e "  ✓ Distribution: ${OS_NAME}"
    fi
else
    OS_NAME="Unknown ($OS_TYPE)"
fi

# ── 2. Prerequisites Check & Automated Remediation ──────────────────────────
echo -e "\n${YELLOW}📦 [Step 2/6] Checking Prerequisites (Python 3.11+, Node.js 18+, Git)...${NC}"

# Python Check
PYTHON_CMD=""
if command -v python3.11 >/dev/null 2>&1; then
    PYTHON_CMD="python3.11"
elif command -v python3 >/dev/null 2>&1; then
    PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

if [ -n "$PYTHON_CMD" ]; then
    echo -e "  ✓ Python detected: $($PYTHON_CMD --version)"
else
    echo -e "  ⚠️ Python 3.11+ is not found in PATH."
    if [ "$OS_TYPE" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            echo -e "  ⚡ Installing python@3.11 via Homebrew..."
            brew install python@3.11
            PYTHON_CMD="python3.11"
        else
            echo -e "  ❌ Homebrew not found. Please install Homebrew or Python 3.11+ manually."
        fi
    elif [ -f /etc/debian_version ]; then
        echo -e "  ⚡ Suggestion: run 'sudo apt update && sudo apt install -y python3.11 python3.11-venv python3-pip'"
    elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
        echo -e "  ⚡ Suggestion: run 'sudo dnf install -y python3.11 python3.11-devel python3-pip'"
    elif [ -f /etc/arch-release ]; then
        echo -e "  ⚡ Suggestion: run 'sudo pacman -S --needed python python-pip'"
    fi
fi

# Node.js Check
if command -v node >/dev/null 2>&1; then
    echo -e "  ✓ Node.js detected: $(node -v)"
else
    echo -e "  ⚠️ Node.js is not found in PATH."
    if [ "$OS_TYPE" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            echo -e "  ⚡ Installing Node.js via Homebrew..."
            brew install node@20
        fi
    elif [ -f /etc/debian_version ]; then
        echo -e "  ⚡ Suggestion: run 'curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs'"
    fi
fi

# Git Check
if command -v git >/dev/null 2>&1; then
    echo -e "  ✓ Git detected: $(git --version)"
fi

# ── 3. Configure .env Environment ───────────────────────────────────────────
echo -e "\n${YELLOW}⚙️ [Step 3/6] Setting up Workspace Environment (.env)...${NC}"
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "  ${GREEN}✓ Created .env from .env.example${NC}"
    else
        cat << 'EOF' > .env
APP_ENV=local
DATABASE_URL=sqlite:///./drishti.db
JWT_SECRET=drishti-local-development-secret-key-32chars
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
DRISHTI_DEMO_MODE=true
AUTO_SEED=true
DEMO_SEED=false
DRISHTI_SERVER_URL=http://localhost:8000
EOF
        echo -e "  ${GREEN}✓ Generated default .env file${NC}"
    fi
else
    echo -e "  ${GREEN}✓ Existing .env file found.${NC}"
fi

# ── 4. Python Backend Setup (server/) ───────────────────────────────────────
echo -e "\n${YELLOW}🐍 [Step 4/6] Bootstrapping FastAPI Server Environment...${NC}"
if [ -n "$PYTHON_CMD" ]; then
    if [ ! -f "server/venv/bin/python" ]; then
        echo -e "  🔨 Creating Python virtual environment in server/venv..."
        $PYTHON_CMD -m venv server/venv
    fi

    echo -e "  📥 Installing server dependencies from requirements.txt..."
    server/venv/bin/pip install --upgrade pip --quiet
    server/venv/bin/pip install -r server/requirements.txt --quiet
    echo -e "  ${GREEN}✓ Backend dependencies installed successfully!${NC}"
else
    echo -e "  ${RED}❌ Skipping backend setup: Python binary not available.${NC}"
fi

# ── 5. Frontend Setup (web/) ────────────────────────────────────────────────
echo -e "\n${YELLOW}🌐 [Step 5/6] Bootstrapping Web SOC Console (React + Vite)...${NC}"
if [ -d "web" ]; then
    echo -e "  📥 Running 'npm install' in web/ directory..."
    (cd web && npm install --silent)
    echo -e "  ${GREEN}✓ Frontend dependencies installed successfully!${NC}"
else
    echo -e "  ${RED}❌ web/ directory not found!${NC}"
fi

# ── 6. Endpoint Agent Setup ─────────────────────────────────────────────────
echo -e "\n${YELLOW}🛡️ [Step 6/6] Verifying Platform Endpoint Agent...${NC}"
if [ "$OS_TYPE" = "Darwin" ]; then
    if [ -f "dist/Drishti-Endpoint-Agent-macOS.pkg" ]; then
        echo -e "  ${GREEN}✓ Standalone macOS package found: dist/Drishti-Endpoint-Agent-macOS.pkg${NC}"
    fi
    if [ -n "$PYTHON_CMD" ] && [ ! -d "endpoint-agent/venv" ]; then
        $PYTHON_CMD -m venv endpoint-agent/venv
        endpoint-agent/venv/bin/pip install -r endpoint-agent/requirements.txt --quiet
        echo -e "  ${GREEN}✓ endpoint-agent venv configured.${NC}"
    fi
elif [ "$OS_TYPE" = "Linux" ]; then
    echo -e "  ℹ️ Linux Endpoint note: passive network watcher is ready at agent/drishti_watch.py"
    if [ -n "$PYTHON_CMD" ] && [ ! -d "endpoint-agent/venv" ]; then
        $PYTHON_CMD -m venv endpoint-agent/venv
        endpoint-agent/venv/bin/pip install -r endpoint-agent/requirements.txt --quiet
        echo -e "  ${GREEN}✓ endpoint-agent venv configured.${NC}"
    fi
fi

# ── Summary & Run Commands ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   🎉 DRISHTI SETUP COMPLETE & READY TO RUN!                        ${NC}"
echo -e "${GREEN}═════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  To launch the platform, run in separate terminal tabs:"
echo ""
echo -e "  👉 TERMINAL 1 (FastAPI Server):"
echo -e "     cd server && source venv/bin/activate"
echo -e "     ${YELLOW}uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload${NC}"
echo ""
echo -e "  👉 TERMINAL 2 (Web SOC Dashboard):"
echo -e "     cd web"
echo -e "     ${YELLOW}npm run dev${NC}"
echo ""
if [ "$OS_TYPE" = "Darwin" ]; then
echo -e "  💡 Tip: You can also start both at once with: ${CYAN}./start-mac.sh${NC}"
fi
echo ""
echo -e "  🌐 Console URL : ${GREEN}http://localhost:5173${NC}"
echo -e "  🔌 API Docs    : ${GREEN}http://localhost:8000/docs${NC}"
echo -e "${GREEN}═════════════════════════════════════════════════════════════════════${NC}"
