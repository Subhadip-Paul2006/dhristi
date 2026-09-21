#!/usr/bin/env bash
# Drishti — Mac Quick Start Script
# Starts backend (FastAPI) + frontend (Vite) in the background
# Usage: ./start-mac.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo -e "${GREEN}   Drishti — Mac Startup Script              ${NC}"
echo -e "${GREEN}════════════════════════════════════════════${NC}"

# ── Kill any old servers ─────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/4] Clearing ports 8000 and 5173...${NC}"
lsof -ti :8000 | xargs kill -9 2>/dev/null || true
lsof -ti :5173 | xargs kill -9 2>/dev/null || true
sleep 1

# ── Backend ──────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/4] Starting FastAPI backend on :8000...${NC}"
if [ ! -f "server/.venv/bin/python" ]; then
  echo -e "${RED}ERROR: server/.venv not found. Run: cd server && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt${NC}"
  exit 1
fi

server/.venv/bin/python -m uvicorn app.main:app \
  --host 0.0.0.0 --port 8000 \
  --log-level info \
  > /tmp/drishti-backend.log 2>&1 &
BACKEND_PID=$!
echo "  Backend PID: $BACKEND_PID  (logs: /tmp/drishti-backend.log)"

# Wait for backend to be ready
echo -e "  Waiting for backend..."
for i in {1..20}; do
  sleep 1
  if curl -sf http://127.0.0.1:8000/health > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Backend is up!${NC}"
    break
  fi
  if [ $i -eq 20 ]; then
    echo -e "${RED}Backend failed to start. Check /tmp/drishti-backend.log${NC}"
    exit 1
  fi
done

# ── Frontend ─────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/4] Starting Vite frontend on :5173...${NC}"
if [ ! -d "web/node_modules" ]; then
  echo "  Installing frontend dependencies..."
  npm install --prefix web --silent
fi

npm run dev --prefix web > /tmp/drishti-frontend.log 2>&1 &
FRONTEND_PID=$!
echo "  Frontend PID: $FRONTEND_PID  (logs: /tmp/drishti-frontend.log)"
sleep 2

# ── Endpoint Agent (optional) ────────────────────────────────────────────────
echo -e "${YELLOW}[4/4] Endpoint Agent setup check...${NC}"
if [ ! -d "endpoint-agent/.venv" ]; then
  echo "  Creating endpoint-agent virtual environment..."
  python3 -m venv endpoint-agent/.venv
  endpoint-agent/.venv/bin/pip install -r endpoint-agent/requirements.txt -q
  echo -e "  ${GREEN}✓ Endpoint agent ready!${NC}"
else
  echo -e "  ${GREEN}✓ Endpoint agent venv exists.${NC}"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo -e "${GREEN}   Drishti is running!                       ${NC}"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo ""
echo -e "  🌐 Dashboard  :  ${GREEN}http://localhost:5173${NC}"
echo -e "  🔌 Backend API:  ${GREEN}http://localhost:8000${NC}"
echo -e "  📚 API Docs   :  ${GREEN}http://localhost:8000/docs${NC}"
echo ""
echo -e "  📧 Login: analyst@acme-retail.dev"
echo -e "  🔑 Pass : drishti-demo"
echo ""
echo -e "  To pair endpoint agent (optional):"
echo -e "    ${YELLOW}endpoint-agent/.venv/bin/python endpoint-agent/cli.py --server http://localhost:8000${NC}"
echo ""
echo -e "  Log files:"
echo -e "    Backend : /tmp/drishti-backend.log"
echo -e "    Frontend: /tmp/drishti-frontend.log"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop...${NC}"

# Keep script alive so Ctrl+C kills everything cleanly
trap "echo -e '\n${YELLOW}Shutting down...${NC}'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Done.'" EXIT INT TERM
wait $BACKEND_PID $FRONTEND_PID
