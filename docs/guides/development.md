# 💻 Developer Guide & Local Environment Setup

> **Target Audience:** Core Contributors, Security Engineers, AI Researchers  
> **Parent Guide:** [CONTRIBUTING.md](../../CONTRIBUTING.md) · [SETUP.md](../../SETUP.md)

---

## 1. Prerequisites

Ensure your host system meets the baseline requirements:
- **Operating System:** Windows 10/11 x64, macOS 12+ (Apple Silicon or Intel), or Linux (Ubuntu 22.04+).
- **Python:** 3.11.x or 3.12.x (`python --version`).
- **Node.js:** 18.x or 20.x LTS (`node --version`) and npm (`npm --version`).
- **Git**

---

## 2. Setting Up the Development Environment

### 2.1 Backend Environment (FastAPI)
```bash
# From repository root:
python -m venv .venv

# Activate virtual environment:
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

# Upgrade pip and install dependencies:
pip install --upgrade pip
pip install -r server/requirements.txt
```

### 2.2 Frontend Environment (React 18 / Vite 5)
```bash
cd web
npm install
cd ..
```

---

## 3. Running Services Locally

### Terminal 1: Backend API Server
```bash
# In active virtual environment:
uvicorn server.app.main:app --host 127.0.0.1 --port 8000 --reload
```
The FastAPI swagger docs will be available at `http://127.0.0.1:8000/docs`.

### Terminal 2: Web Console (Dev Server)
```bash
cd web
npm run dev
```
The Vite development server will start at `http://localhost:5173`.

---

## 4. Running the Automated Test Suites

### 4.1 Backend Pytest Suite
```bash
# Run all 408 tests with verbose output:
pytest server/tests/ -v

# Run with test coverage:
pytest server/tests/ --cov=server/app
```

### 4.2 Frontend Vitest Suite
```bash
cd web
npm test
```

### 4.3 Strict Type Checking & Linting
```bash
# Backend code formatting:
black --check server/
flake8 server/

# Frontend TypeScript compiler check:
cd web
npx tsc -b --noEmit
```
