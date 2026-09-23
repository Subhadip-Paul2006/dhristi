# 🚀 Deployment Guide & Operational Architecture

> **Parent Specification:** [SETUP.md](../../SETUP.md) · [TRD.md](../../TRD.md)  
> **Deployment Status:** Public Frontend Preview (Vercel) + On-Premise/Local Full-Stack Core

---

## 1. Deployment Transparency & Architecture Model

Drishti utilizes an intentional two-tier deployment architecture:

```text
┌──────────────────────────────────────────────┐
│  TIER A: PUBLIC FRONTEND PREVIEW (VERCEL)    │
│  - Hosted on Vercel Edge Global Network      │
│  - Environment: VITE_DEMO_MODE=true          │
│  - Zero backend dependency                   │
│  - Instant, interactive evaluator walkthrough│
└──────────────────────────────────────────────┘
                       ▲
                       │ Evaluation Boundary
                       ▼
┌──────────────────────────────────────────────┐
│  TIER B: ENTERPRISE FULL-STACK (ON-PREM)     │
│  - Python 3.11+ / FastAPI Core               │
│  - Low-level kernel packet drivers (Npcap)   │
│  - Anthropic Claude 3.5 Sonnet Integration   │
│  - Cross-platform endpoint daemons           │
│  - Complete end-to-end verified environment  │
└──────────────────────────────────────────────┘
```

### Why the Backend is On-Premise / Local
1. **Paid External API Credentials:** The backend integrates with proprietary, paid cloud intelligence services, including the **Anthropic Claude API** (`ANTHROPIC_API_KEY`), **Google Safe Browsing API**, and **VirusTotal Intelligence API**. To protect API quotas and maintain credential confidentiality, these keys are never deployed to an unauthenticated public endpoint.
2. **Kernel Driver & Raw Socket Requirements:** Drishti’s passive sniffing and Live Watch capabilities rely on low-level operating system drivers (`AF_PACKET` on Linux, `/dev/bpf*` on macOS, and Npcap on Windows) to capture wire-speed packets. Serverless hosting platforms (such as Vercel or AWS Lambda) strictly prohibit raw socket bindings and promiscuous network capture.
3. **End-to-End Proof:** The complete full-stack system has been comprehensively verified and tested end-to-end, with 408 backend tests passing. Full-stack workflows are demonstrated in the submitted evaluation videos and reproducible locally via [SETUP.md](../../SETUP.md).

---

## 2. Deploying the Frontend to Vercel (Demo Mode)

The web frontend is pre-configured for instant zero-configuration deployment to Vercel:

1. **Vercel Project Configuration:**
   - **Root Directory:** `web`
   - **Framework Preset:** Vite
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
2. **Environment Variables on Vercel:**
   Set the following environment variable in the Vercel Dashboard (**Settings > Environment Variables**):
   ```text
   VITE_DEMO_MODE = true
   ```
3. Deploy! The frontend will serve an interactive, fully functional preview using deterministic synthetic telemetry.

---

## 3. Deploying the Full-Stack Backend On-Premise

### 3.1 Native Linux Systemd Deployment
1. **Clone & Set Up Directory:**
   ```bash
   sudo mkdir -p /opt/drishti
   sudo chown -R $USER:$USER /opt/drishti
   git clone https://github.com/Subhadip-Paul2006/dhristi.git /opt/drishti
   cd /opt/drishti
   ```
2. **Virtual Environment & Dependencies:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r server/requirements.txt
   ```
3. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your database URL, JWT secret, and Anthropic API key:
   nano .env
   ```
4. **Create Systemd Service (`/etc/systemd/system/drishti-backend.service`):**
   ```ini
   [Unit]
   Description=Drishti Cybersecurity Intelligence Backend
   After=network.target

   [Service]
   User=drishti
   WorkingDirectory=/opt/drishti
   ExecStart=/opt/drishti/.venv/bin/uvicorn server.app.main:app --host 0.0.0.0 --port 8000 --workers 4
   Restart=always
   RestartSec=5
   EnvironmentFile=/opt/drishti/.env

   [Install]
   WantedBy=multi-user.target
   ```
5. **Start & Enable:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now drishti-backend
   ```

---

## 4. Production Security Hardening Checklist

- [ ] Ensure `DRISHTI_ENV=production` is set in `.env`.
- [ ] Generate high-entropy 32-byte JWT secret (`openssl rand -hex 32`).
- [ ] Configure PostgreSQL with connection pooling.
- [ ] Put backend behind NGINX or Caddy with automated Let's Encrypt TLS 1.3 certificates.
- [ ] Restrict database ports (`5432`) to the local host interface.
- [ ] Configure `ALLOWED_CORS_ORIGINS` to only permit authorized console domains.
