# 👁️ Drishti

> **See the invisible. Price the risk. Fix it first.**

Drishti is a defensive cybersecurity platform that maps your network, prices every attack path in real dollars, and generates Ansible playbooks to close the gaps — before adversaries find them. Built on a graph-theoretic attack-surface engine, Drishti turns infrastructure chaos into actionable, prioritized remediation.

---

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![NetworkX](https://img.shields.io/badge/NetworkX-3.4-2C5AA0)
![Tailwind](https://img.shields.io/badge/Tailwind-3.4-06B6D4?logo=tailwindcss&logoColor=white)

**Defensive only. Maps, prices, and remediates. Never attacks.**

</div>

---

## 📑 Table of Contents

- [What Drishti Does](#-what-drishti-does)
- [Architecture Overview](#-architecture-overview)
- [System Architecture (C4)](#-system-architecture-c4)
- [Data Flow](#-data-flow)
- [Backend Deep Dive](#-backend-deep-dive)
- [Attack Graph Engine](#-attack-graph-engine)
- [Risk Scoring Model](#-risk-scoring-model)
- [Recompute & Exposure Tracking](#-recompute--exposure-tracking)
- [Authentication & Security](#-authentication--security)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Tech Stack](#-tech-stack)
- [Repository Map](#-repository-map)
- [Testing](#-testing)
- [Demo Network — Acme Retail](#-demo-network--acme-retail)
- [Documentation](#-documentation)
- [Contributing](#-contributing)

---

## 🎯 What Drishti Does

| Capability | What It Means |
|---|---|
| **Network Discovery** | Agents auto-discover devices via DNS, connection tables, and mDNS — zero manual entry |
| **Attack Graph** | NetworkX builds a directed graph of every asset; Yen's algorithm finds all Internet→crown-jewel paths |
| **Risk Pricing** | CVSS × criticality × blast radius → dollar exposure per asset and per attack path |
| **Breach Simulation** | Step through how an attacker would traverse your network, hop by hop |
| **Live Watch** | Real-time device telemetry with a force-directed topology map |
| **AI Remediation** | LLM-assisted remediation plans + Ansible playbook generation |
| **URL Trust** | Heuristic + ML scoring for URL reputation with WHOIS lookup |
| **Deep Scan** | Autonomous nmap scanning triggered on schedule or on demand |
| **Telegram Alerts** | Real-time push notifications for critical findings |
| **Chrome Guard** | MV3 extension that blocks malicious URLs at the browser |

---

## 🏗️ Architecture Overview

Drishti is a multi-tier, defensive security platform with four runtime planes:

```
┌─────────────────────────────────────────────────────────┐
│ 👤 Security Analyst │
│ ┌───────────────────────────────────────────────────┐ │
│ │ 🌐 Web UI (React + Vite + ReactFlow) │ │
│ │ Port 5173 · 12 feature modules │ │
│ └────────────────────┬──────────────────────────────┘ │
└───────────────────────┼─────────────────────────────────┘
 │ HTTPS (JWT Bearer)
 ▼
┌─────────────────────────────────────────────────────────┐
│ 🖥️ Backend API (FastAPI + SQLAlchemy) │
│ Port 8000 · 16 REST routers · 10 ORM models │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ Risk │ │ Attack │ │ Deep │ │ URL │ │
│ │ Engine │ │ Paths │ │ Scan │ │ Trust │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ Live │ │ Intel │ │ Hardening│ │ Telegram │ │
│ │ Watch │ │ Feeds │ │ (Ansible)│ │ Alerts │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
└────────┬──────────────┬──────────────┬─────────────────┘
 │ │ │
 ┌────▼────┐ ┌────▼────┐ ┌────▼────┐
 │ SQLite │ │ Redis │ │ NVD │
 │ (Dev) │ │(Cache) │ │ API │
 └─────────┘ └─────────┘ └─────────┘
 ▲
 │ ingest / polling
 ┌────┴──────────────────────────────┐
 │ 👁️ Edge Agent (Python stdlib) │
 │ Device discovery · mDNS · DNS │
 │ Connection tables · Live watch │
 └───────────────────────────────────┘
 ▲
 │
 ┌────┴──────────────────────────────┐
 │ 🧩 Chrome Extension (MV3) │
 │ URL blocking · Warning page │
 └───────────────────────────────────┘
```

---

## 🏛️ System Architecture (C4)

### C1 — System Context

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
graph TB
 subgraph EXTERNAL [" "]
 direction TB
 ANALYST["👤 Security Analyst<br/><i>Pricing, triage, remediation</i>"]
 NVD["🌐 NVD API<br/><i>CVE database</i>"]
 TELEGRAM["💬 Telegram<br/><i>Push alerts</i>"]
 DNS["🔍 DNS / mDNS<br/><i>Device discovery</i>"]
 NMAP["🔎 nmap<br/><i>Deep scanner</i>"]
 end

 subgraph DRISHTI ["👁️ Drishti Platform"]
 direction LR
 WEB["🌐 Web UI<br/>React + TypeScript"]
 API["🖥️ Backend API<br/>FastAPI"]
 AGENT["👁️ Edge Agent<br/>Python stdlib"]
 EXT["🧩 Chrome Extension<br/>Manifest V3"]
 end

 ANALYST -->|HTTPS + JWT| WEB
 WEB -->|REST / JSON| API
 AGENT -->|POST /ingest| API
 EXT -->|POST /urltrust| API
 API -->|CVE lookup| NVD
 API -->|Push notifications| TELEGRAM
 AGENT -->|mDNS / DNS queries| DNS
 API -->|subprocess| NMAP

 style ANALYST fill:#1a1a2e,stroke:#38c6f4,color:#e0e0e0
 style WEB fill:#0f3460,stroke:#e94560,color:#fff
 style API fill:#0f3460,stroke:#e94560,color:#fff
 style AGENT fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style EXT fill:#16213e,stroke:#38c6f4,color:#e0e0e0
```

### C2 — Container Diagram

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
graph LR
 subgraph CLIENT ["Client Tier"]
 WEB["🌐 Web SPA<br/>React 18 · Vite 5<br/>ReactFlow · Recharts"]
 EXT["🧩 Chrome Extension<br/>MV3 · Service Worker<br/>Block page + caching"]
 end

 subgraph SERVER ["Server Tier — FastAPI 0.115"]
 ROUTERS["📡 16 REST Routers<br/>api/v1/*.py + api/*.py"]
 SERVICES["⚙️ 14 Service Modules<br/>services/*.py"]
 MODELS["🗄️ 10 ORM Models<br/>SQLAlchemy 2.0 + Alembic"]
 AUTH["🔐 Auth Layer<br/>JWT 15m/7d + bcrypt"]
 CORE["🛡️ Core<br/>Rate-limit · Errors · Deps"]
 end

 subgraph AGENT ["Edge Tier"]
 WATCH["drishti_watch.py<br/>Live daemon<br/>DNS/mDNS/conn/devices"]
 INGEST["drishti_agent.py<br/>Snapshot ingester<br/>Fixture replay"]
 end

 subgraph DATA ["Data Tier"]
 DB["🗄️ SQLite / PostgreSQL<br/>21 tables · Alembic migrations"]
 CACHE["⚡ Redis<br/>Session cache · Rate limits"]
 end

 subgraph EXTERNAL ["External Services"]
 NVD_SVC["NVD API<br/>CVE enrichment"]
 TG["Telegram Bot API<br/>Alert push"]
 LLM["LLM Provider<br/>AI remediation + chat"]
 end

 WEB -->|HTTPS + JWT| ROUTERS
 EXT -->|HTTPS + Bearer| ROUTERS
 ROUTERS --> AUTH
 ROUTERS --> SERVICES
 SERVICES --> MODELS
 MODELS --> DB
 SERVICES --> CACHE
 AGENT -->|ingest| ROUTERS

 SERVICES -.->|CVE lookup| NVD_SVC
 SERVICES -.->|notify| TG
 SERVICES -.->|AI calls| LLM

 style WEB fill:#0f3460,stroke:#e94560,color:#fff
 style EXT fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style ROUTERS fill:#0f3460,stroke:#e94560,color:#fff
 style SERVICES fill:#0f3460,stroke:#e94560,color:#fff
 style MODELS fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style DB fill:#16213e,stroke:#f4d03f,color:#1a1a2e
 style AGENT fill:#16213e,stroke:#38c6f4,color:#e0e0e0
```

### C3 — Backend Service Layer

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
graph TB
 subgraph API_LAYER ["📡 API Routers (16 endpoints)"]
 HEALTH["health"]
 AUTH_R["auth"]
 ORG_R["org"]
 INGEST_R["ingest"]
 ASSETS_R["assets"]
 FINDINGS_R["findings"]
 GRAPH_R["graph"]
 PATHS_R["paths"]
 AI_R["ai"]
 DASH_R["dashboard"]
 REPORT_R["report"]
 LIVE_R["live"]
 NET_R["netconfig"]
 URL_R["urltrust"]
 SCAN_R["scan"]
 ADMIN_R["admin"]
 end

 subgraph SERVICE_LAYER ["⚙️ Service Layer"]
 RISK["risk_engine.py<br/>NetworkX DiGraph<br/>Node pricing"]
 ATK["attack_paths.py<br/>Yen's k-shortest<br/>Path enumeration"]
 IMPACT["impact.py<br/>Dollar scoring<br/>CVSS × blast radius"]
 RECOMP["recompute.py<br/>Exposure delta<br/>Live recompute"]
 INGEST_S["ingest.py<br/>Agent payload<br/>processing"]
 URLTRUST["urltrust/<br/>Heuristic + ML<br/>scoring"]
 DEEPSCAN["deepscan/<br/>nmap scanner<br/>CVE integration"]
 NETCONF["netconfig/<br/>Cisco config<br/>generation"]
 LIVE_S["live.py<br/>Watch orchestration"]
 INTEL["intel.py<br/>Threat feed<br/>integration"]
 AUTOSCAN["autoscan.py<br/>Scheduled scans"]
 HARD["hardening.py<br/>Ansible playbooks"]
 TG_ALERT["telegram_alerts.py<br/>Push notifications"]
 AI_SVC["ai/<br/>LLM chat + remediation"]
 ACCOUNTS["accounts.py<br/>User management"]
 DASH_SVC["dashboard_service.py<br/>Metrics aggregation"]
 end

 subgraph DATA_LAYER ["🗄️ Data Layer"]
 ORG_M["org.py"]
 ASSET_M["asset.py"]
 VULN_M["vuln.py"]
 FINDING_M["finding.py"]
 PATH_M["path.py"]
 SCAN_M["scan.py"]
 REM_M["remediation.py"]
 LIVE_M["live.py"]
 NET_M["netconfig.py"]
 URL_M["urltrust.py"]
 end

 API_LAYER --> SERVICE_LAYER
 SERVICE_LAYER --> DATA_LAYER

 style HEALTH fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style AUTH_R fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style RISK fill:#0f3460,stroke:#e94560,color:#fff
 style ATK fill:#0f3460,stroke:#e94560,color:#fff
 style AI_SVC fill:#16213e,stroke:#f4d03f,color:#1a1a2e
 style DEEPSCAN fill:#16213e,stroke:#f4d03f,color:#1a1a2e
```

---

## 🔄 Data Flow

### End-to-End: From Discovery to Remediation

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
flowchart TD
 subgraph DISCOVERY ["Phase 1 — Discovery"]
 direction LR
 D1["👁️ Agent<br/>dns/conn/devices scan"]
 D2["🔎 Deep Scan<br/>nmap + NVD CVE"]
 D3["🧩 Extension<br/>URL telemetry"]
 end

 subgraph INGEST ["Phase 2 — Ingestion"]
 I1["📥 POST /api/v1/ingest<br/>JSON payload"]
 I2["🔍 Validate + Transform<br/>Pydantic schemas"]
 I3["💾 Persist<br/>SQLAlchemy ORM"]
 end

 subgraph ANALYSIS ["Phase 3 — Graph Analysis"]
 direction TB
 A1["🕸️ Build NetworkX DiGraph<br/>Nodes = assets<br/>Edges = reachability"]
 A2["🔍 Yen's k-Shortest<br/>All Internet→jewel paths"]
 A3["💰 Price Every Path<br/>CVSS × blast radius × $"]
 A4["📊 Aggregate Exposure<br/>Total $ at risk"]
 end

 subgraph TRIGGER ["Phase 4 — Event-Driven Recompute"]
 T1["✅ Finding resolved"]
 T2["🆕 New finding"]
 T3["💎 Asset added/removed"]
 T4["🔧 Vuln patched"]
 T5["🗑️ Asset removed"]
 end

 subgraph OUTPUT ["Phase 5 — Output"]
 direction LR
 O1["📊 Dashboard<br/>Exposure KPIs"]
 O2["🕸️ Attack Map<br/>ReactFlow visualization"]
 O3["🔍 Breach Sim<br/>Step-by-step paths"]
 O4["🚨 Findings<br/>Severity-ranked table"]
 O5["🛠️ Remediation<br/>Ansible playbooks"]
 O6["💬 Telegram<br/>Push alerts"]
 O7["📡 Live Watch<br/>Force-directed map"]
 end

 D1 -->|HTTPS POST| I1
 D2 -->|scheduled| I2
 D3 -->|HTTPS POST| I1

 I1 --> I2 --> I3
 I3 --> A1 --> A2 --> A3 --> A4

 T1 & T2 & T3 & T4 & T5 -.->|trigger| A1

 A4 --> O1 & O2 & O3 & O4 & O5 & O6 & O7

 style D1 fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style A1 fill:#0f3460,stroke:#e94560,color:#fff
 style T1 fill:#16213e,stroke:#f4d03f,color:#1a1a2e
```

### Request Lifecycle: Auth → Data → Response

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
sequenceDiagram
 actor U as 👤 Analyst
 participant W as 🌐 Web UI
 participant A as 🖥️ API Gateway
 participant S as ⚙️ Service Layer
 participant D as 🗄️ Database
 participant G as 🕸️ Graph Engine

 U->>W: Login (email + password)
 W->>A: POST /api/v1/auth/login
 A->>A: Verify bcrypt hash
 A-->>W: JWT access (15m) + refresh (7d)
 W->>A: GET /api/v1/dashboard + Bearer token
 A->>A: Validate JWT + org membership
 A->>S: get_dashboard(org_id)
 S->>D: Query assets + findings
 D-->>S: Asset/finding rows
 S->>G: build_graph(assets)
 G->>G: NetworkX DiGraph + Yen's k-shortest
 G-->>S: Attack paths + dollar prices
 S-->>A: Aggregated metrics + paths
 A-->>W: JSON response
 W->>U: Render dashboard with KPIs
```

---

## ⚙️ Backend Deep Dive

### Backend Service Topology

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
graph TB
 subgraph SECURITY ["🔐 Security & Auth"]
 AUTH["auth.py<br/>JWT + bcrypt<br/>login/refresh/me"]
 DEPS["deps.py<br/>get_current_user<br/>rate limiting"]
 ERRORS["errors.py<br/>HTTPException handlers<br/>envelope format"]
 end

 subgraph BUSINESS ["⚙️ Business Logic — 14 Services"]
 RISK["risk_engine.py<br/>Graph construction<br/>Node pricing"]
 ATK["attack_paths.py<br/>Yen's k-shortest<br/>Path enumeration"]
 IMPACT["impact.py<br/>Dollar value<br/>CVSS × blast radius"]
 RECOMP["recompute.py<br/>Exposure recompute<br/>on events"]
 INGEST_S["ingest.py<br/>Agent payload<br/>normalization"]
 URLTRUST["urltrust/<br/>6-module scoring<br/>heuristic + ML"]
 DEEPSCAN["deepscan/<br/>nmap integration<br/>CVE lookup"]
 NETCONF["netconfig/<br/>Cisco config<br/>generation"]
 LIVE["live.py<br/>Device orchestration<br/>mDNS + DNS"]
 INTEL["intel.py<br/>Threat feeds<br/>enrichment"]
 AUTOSCAN["autoscan.py<br/>Scheduled scans<br/>APScheduler"]
 HARD["hardening.py<br/>Ansible<br/>playbooks"]
 TG["telegram_alerts.py<br/>Bot notifications"]
 AI["ai/<br/>LLM client +<br/>prompts + service"]
 ACC["accounts.py<br/>User + org<br/>management"]
 DASH["dashboard_service.py<br/>Metrics<br/>aggregation"]
 end

 subgraph SEED ["🌱 Demo Data"]
 ACME["acme.py<br/>Acme Retail<br/>network seed"]
 FIXTURES["fixtures/<br/>JSON scan<br/>data"]
 end

 SECURITY --> BUSINESS
 BUSINESS --> SEED

 style AUTH fill:#0f3460,stroke:#e94560,color:#fff
 style RISK fill:#0f3460,stroke:#e94560,color:#fff
 style ATK fill:#0f3460,stroke:#e94560,color:#fff
 style AI fill:#16213e,stroke:#f4d03f,color:#1a1a2e
 style DEEPSCAN fill:#16213e,stroke:#f4d03f,color:#1a1a2e
```

---

## 🕸️ Attack Graph Engine

The core of Drishti. Every asset becomes a node, every reachability relationship becomes a directed edge, and graph algorithms find what matters.

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
flowchart TD
 subgraph INPUT ["📥 Input: Assets + Topology"]
 A1["🌐 Internet<br/>(Entry point)"]
 A2["🔀 DMZ<br/>web.acme-retail.dev<br/>CVSS 7.5 · $45K"]
 A3["⚙️ App Server<br/>api.acme-retail.dev<br/>CVSS 9.8 · $180K"]
 A4["💎 Crown Jewel<br/>db.acme-retail.dev<br/>CVSS 9.1 · $500K"]
 A5["📧 Mail Server<br/>mail.acme-retail.dev<br/>CVSS 6.1 · $15K"]
 A6["🔐 VPN Gateway<br/>vpn.acme-retail.dev<br/>CVSS 7.8 · $90K"]
 A7["📊 Monitor<br/>monitor.acme-retail.dev<br/>CVSS 4.3 · $8K"]
 end

 subgraph GRAPH ["🕸️ NetworkX DiGraph"]
 NODES["Nodes: 7 assets<br/>+ Internet"]
 EDGES["Edges: Reachability<br/>DMZ→App→DB<br/>VPN→App<br/>VPN→Monitor"]
 PRICING["Node Price = Σ(CVSS×0.4,<br/>Criticality×0.3,<br/>Exposure×0.2,<br/>Blast×0.1)"]
 end

 subgraph ALGO ["🔬 Graph Algorithms"]
 YEN["Yen's k-Shortest<br/>All Internet→DB paths<br/>k = configurable"]
 BLOCK["Network Min-Cut<br/>Critical route<br/>identification"]
 BLAST["Blast Radius<br/>Downstream impact<br/>per compromised node"]
 end

 subgraph OUTPUT ["📤 Output"]
 PATHS_OUT["Attack Paths<br/>Internet→DMZ→App→DB<br/>3 hops · $725K exposure"]
 SCORE_OUT["Risk Scores<br/>Per-node + per-path<br/>Dollar + severity"]
 REM_OUT["Remediation<br/>Priority-ranked<br/>by $ impact"]
 end

 A1 & A2 & A3 & A4 & A5 & A6 & A7 --> NODES
 NODES --> EDGES --> PRICING
 PRICING --> YEN --> BLOCK --> BLAST
 BLAST --> PATHS_OUT & SCORE_OUT & REM_OUT

 style A4 fill:#0f3460,stroke:#f4d03f,stroke-width:3px,color:#f4d03f
 style A2 fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style YEN fill:#0f3460,stroke:#e94560,color:#fff
 style PATHS_OUT fill:#16213e,stroke:#f4d03f,color:#1a1a2e
```

### Attack Path Enumeration

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
flowchart LR
 subgraph SOURCE ["Source"]
 INTERNET["🌐 Internet<br/>(Untrusted)"]
 end

 subgraph PATH1 ["Path 1 — Primary (3 hops)"]
 P1S["🌐 Internet"]
 P1A["DMZ Web<br/>7.5 CVSS"]
 P1B["App Server<br/>9.8 CVSS"]
 P1C["💎 Database<br/>9.1 CVSS · $500K"]
 end

 subgraph PATH2 ["Path 2 — Alternative (2 hops)"]
 P2S["🌐 Internet"]
 P2A["🔐 VPN Gateway<br/>7.8 CVSS"]
 P2B["💎 Database<br/>9.1 CVSS · $500K"]
 end

 subgraph PATH3 ["Path 3 — Lateral (3 hops)"]
 P3S["🌐 Internet"]
 P3A["📧 Mail Server<br/>6.1 CVSS"]
 P3B["📊 Monitor<br/>4.3 CVSS"]
 P3C["🔐 VPN Gateway<br/>7.8 CVSS"]
 end

 subgraph RESULTS ["Results"]
 R1["🥇 Path 1: $725K · CRITICAL"]
 R2["🥈 Path 2: $590K · CRITICAL"]
 R3["🥉 Path 3: $118K · HIGH"]
 end

 INTERNET --> P1S --> P1A --> P1B --> P1C --> R1
 INTERNET --> P2S --> P2A --> P2B --> R2
 INTERNET --> P3S --> P3A --> P3B --> P3C --> R3

 style P1C fill:#0f3460,stroke:#f4d03f,stroke-width:3px,color:#f4d03f
 style P2B fill:#0f3460,stroke:#f4d03f,stroke-width:3px,color:#f4d03f
 style R1 fill:#e94560,stroke:#ff6b6b,color:#fff
 style R2 fill:#e94560,stroke:#ff6b6b,color:#fff
 style R3 fill:#0f3460,stroke:#f4d03f,color:#f4d03f
```

---

## 📊 Risk Scoring Model

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
flowchart LR
 classDef input fill:#16213e,stroke:#38c6f4,stroke-width:2px,color:#e0e0e0
 classDef weight fill:#e94560,stroke:#ff6b6b,stroke-width:1.5px,color:#fff
 classDef calc fill:#0f3460,stroke:#f4d03f,stroke-width:2px,color:#f4d03f
 classDef out fill:#16213e,stroke:#38c6f4,stroke-width:2px,color:#e0e0e0

 subgraph INPUTS ["📥 Inputs"]
 F1["📋 CVSS Base Score<br/>0.0 – 10.0"]:::input
 F2["💎 Asset Criticality<br/>1× – 5× multiplier"]:::input
 F3["🌐 Exposure Score<br/>Public vs Segmented"]:::input
 F4["💥 Blast Radius<br/>Downstream impact"]:::input
 end

 subgraph WEIGHTS ["⚖️ Weighted Formula"]
 W1["40%"]:::weight
 W2["30%"]:::weight
 W3["20%"]:::weight
 W4["10%"]:::weight
 end

 subgraph FORMULAS ["🧮 Calculations"]
 NODE["Node Price =<br/>(CVSS × 0.40) +<br/>(Criticality × 0.30) +<br/>(Exposure × 0.20) +<br/>(Blast × 0.10)"]:::calc
 PATH["Path Cost = Σ(Exploit Cost)<br/>+ BlastRadius × CrownJewel"]:::calc
 end

 subgraph OUTPUT ["📤 Output"]
 O1["🎯 Node Score<br/>0 – 10"]
 O2["💰 Dollar Price<br/>$0 – $1M+"]
 O3["⚠️ Severity<br/>Critical / High / Med / Low"]
 end

 F1 --> W1
 F2 --> W2
 F3 --> W3
 F4 --> W4
 W1 & W2 & W3 & W4 --> NODE
 NODE --> PATH
 PATH --> O1 & O2 & O3
```

---

## 🔄 Recompute & Exposure Tracking

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
flowchart TD
 classDef trigger fill:#e94560,stroke:#ff6b6b,stroke-width:2px,color:#fff
 classDef step fill:#16213e,stroke:#38c6f4,stroke-width:1.5px,color:#e0e0e0
 classDef result fill:#0f3460,stroke:#f4d03f,stroke-width:2px,color:#f4d03f

 subgraph TRIGGERS ["⚡ Trigger Events"]
 direction LR
 T1["✅ Finding<br/>Resolved"]:::trigger
 T2["🆕 New Finding<br/>Created"]:::trigger
 T3["🖥️ New Asset<br/>Discovered"]:::trigger
 T4["🔧 Vuln<br/>Patched"]:::trigger
 T5["🗑️ Asset<br/>Removed"]:::trigger
 end

 subgraph PIPELINE ["⚙️ Recompute Pipeline — 7 Steps"]
 direction TB
 S1["1️⃣ Load Org Assets<br/>All nodes in org graph"]:::step
 S2["2️⃣ Rebuild NetworkX<br/>Directed DiGraph"]:::step
 S3["3️⃣ Yen's k-Shortest<br/>All INTERNET → jewel paths"]:::step
 S4["4️⃣ Price Each Path<br/>$ CVSS × blast radius"]:::step
 S5["5️⃣ Min-Cut Analysis<br/>Critical routes"]:::step
 S6["6️⃣ Aggregate Exposure<br/>Total $ at risk"]:::step
 S7["7️⃣ Store + Emit<br/>Updated metrics"]:::step
 end

 subgraph RESULTS ["📊 Results Dashboard"]
 direction LR
 R1["💰 Total Exposure"]:::result
 R2["📈 Top Risk Path"]:::result
 R3["👑 Crown Jewels"]:::result
 R4["📉 Trend"]:::result
 R5["🚨 Open Findings"]:::result
 end

 T1 & T2 & T3 & T4 & T5 --> S1
 S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7
 S7 --> R1 & R2 & R3 & R4 & R5
```

---

## 🔐 Authentication & Security

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
sequenceDiagram
 actor U as 👤 User
 participant W as 🌐 Web UI
 participant A as 🖥️ API
 participant DB as 🗄️ Database

 U->>W: Enter credentials
 W->>A: POST /api/v1/auth/login<br/>{email, password}
 A->>DB: SELECT user WHERE email
 DB-->>A: User record
 A->>A: bcrypt.verify(password, hash)
 alt Valid credentials
 A->>A: Create JWT (15m access + 7d refresh)
 A-->>W: {access_token, refresh_token, org}
 W->>W: Store tokens (memory / httpOnly cookie)
 W->>A: GET /api/v1/dashboard<br/>Authorization: Bearer <token>
 A->>A: JWT decode + verify signature
 A->>A: Check org membership
 A-->>W: Protected data
 else Invalid
 A-->>W: 401 Unauthorized
 W->>U: Show error
 end

 Note over A,W: Every request carries Bearer JWT<br/>Rate-limited per org
 Note over A,DB: Passwords: bcrypt 12 rounds<br/>Never returned in responses
```

---

## 🚀 Deployment Architecture

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
graph TB
 subgraph DEV ["Development"]
 direction LR
 UVICORN["uvicorn<br/>--reload"]
 VITE["vite dev<br/>HMR"]
 REDIS_D["redis-server"]
 SQLITE_D["drishti.db"]
 end

 subgraph PROD ["Production (Docker)"]
 direction LR
 API_P["FastAPI<br/>Gunicorn + Uvicorn<br/>workers × N"]
 WEB_P["Nginx<br/>Serves SPA<br/>reverse proxy /api"]
 REDIS_P["Redis<br/>Session + cache"]
 DB_P["PostgreSQL<br/>Primary + read replica"]
 SCHED["APScheduler<br/>Deep scan cron"]
 end

 subgraph CI ["CI/CD"]
 GH["GitHub Actions"]
 DOCKER["Docker Build"]
 TEST["pytest + Vitest"]
 DEPLOY["Deploy"]
 end

 GH -->|push| TEST
 TEST -->|pass| DOCKER
 DOCKER -->|image| DEPLOY
 DEPLOY --> API_P
 DEPLOY --> WEB_P

 UVICORN --> API_P
 VITE --> WEB_P

 style UVICORN fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style API_P fill:#0f3460,stroke:#e94560,color:#fff
 style WEB_P fill:#0f3460,stroke:#e94560,color:#fff
 style GH fill:#16213e,stroke:#f4d03f,color:#1a1a2e
```

---

## ✨ Features

### Feature Map

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
graph TB
 subgraph VISUALIZE ["📊 Visualize"]
 DASH["📈 Dashboard<br/>KPI cards · exposure<br/>trends · severity split"]
 GRAPH_MAP["🕸️ Attack Map<br/>ReactFlow force graph<br/>blast radius coloring"]
 LIVE_MAP["📡 Live Watch<br/>Real-time topology<br/>mDNS discovery"]
 end

 subgraph ANALYZE ["🔬 Analyze"]
 BREACH["🔍 Breach Simulation<br/>Yen's paths<br/>step-by-step walkthrough"]
 FINDINGS_TBL["🚨 Findings<br/>Severity-ranked<br/>filterable · searchable"]
 URLTRUST_UI["🌐 URL Analyzer<br/>Reputation score<br/>WHOIS · heuristic · ML"]
 end

 subgraph ACT ["🛠️ Act"]
 REMED["🛠️ Remediation Studio<br/>3-column layout<br/>Ansible playbook gen"]
 AI_CHAT["💬 AI Assistant<br/>LLM-powered chat<br/>remediation advice"]
 REPORT_GEN["📋 Reports<br/>Full org export<br/>NetConfig download"]
 end

 subgraph DETECT ["👁️ Detect"]
 DEEP_SCAN["🔎 Deep Scan<br/>nmap autonomous<br/>NVD CVE lookup"]
 AUTO_SCAN["⏰ Auto Scan<br/>Scheduled triggers<br/>APScheduler"]
 THREAT_FEED["🌡️ Threat Intel<br/>Live feed integration<br/>enrichment"]
 end

 subgraph ALERT ["🔔 Alert"]
 TG_BOT["💬 Telegram<br/>Critical finding<br/>push alerts"]
 BLOCK_PAGE["🧩 Chrome Guard<br/>URL blocking<br/>warning page"]
 end

 subgraph MANAGE ["⚙️ Manage"]
 AUTH_MGMT["🔐 Auth<br/>JWT · org mgmt<br/>multi-tenant"]
 SETTINGS["⚙️ Settings<br/>Org config<br/>preferences"]
 end

 VISUALIZE --> ANALYZE --> ACT --> DETECT --> ALERT --> MANAGE

 style DASH fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style GRAPH_MAP fill:#0f3460,stroke:#e94560,color:#fff
 style BREACH fill:#0f3460,stroke:#e94560,color:#fff
 style REMED fill:#16213e,stroke:#f4d03f,color:#1a1a2e
 style DEEP_SCAN fill:#16213e,stroke:#f4d03f,color:#1a1a2e
 style TG_BOT fill:#16213e,stroke:#38c6f4,color:#e0e0e0
```

### Backend Architecture: Data Flow in Detail

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
flowchart TD
 subgraph REQUEST ["Incoming Request"]
 CLIENT["Client<br/>(Web / Agent / Extension)"]
 MIDDLEWARE["FastAPI Middleware<br/>CORS · Rate Limit · Auth"]
 end

 subgraph ROUTING ["Router Layer"]
 R1["16 REST Routers<br/>Route → Service"]
 end

 subgraph SERVICE ["Service Execution"]
 S1["Service Method<br/>(e.g. get_attack_paths)"]
 S2["Graph Engine<br/>NetworkX + Yen's"]
 S3["External Calls<br/>NVD · Telegram · LLM"]
 end

 subgraph DB_LAYER ["Database Layer"]
 D1["Pydantic Schema<br/>DTO validation"]
 D2["SQLAlchemy ORM<br/>10 models · 21 tables"]
 D3["Alembic Migrations<br/>Schema versioning"]
 end

 subgraph RESPONSE ["Response"]
 RSP["JSON Response<br/>Pydantic serialized"]
 WS["WebSocket (optional)<br/>Live telemetry"]
 end

 CLIENT --> MIDDLEWARE --> R1 --> S1
 S1 --> S2
 S1 --> S3
 S1 --> D1 --> D2 --> D3
 D2 --> S1
 S1 --> RSP --> CLIENT
 S1 -.->|optional| WS --> CLIENT

 style S1 fill:#0f3460,stroke:#e94560,color:#fff
 style S2 fill:#0f3460,stroke:#f4d03f,color:#1a1a2e
 style D2 fill:#16213e,stroke:#38c6f4,color:#e0e0e0
 style MIDDLEWARE fill:#16213e,stroke:#38c6f4,color:#e0e0e0
```

---

## 🚀 Quick Start

### 🐳 Option A: Docker Compose (Recommended for Teams)

The fastest and most reliable way to run Drishti across **macOS (Apple Silicon & Intel)**, **Linux (Arch, Debian, Ubuntu, Fedora)**, and **Windows** without manually installing or matching Python/Node dependencies.

#### 1. Prerequisites
- [Docker Engine](https://docs.docker.com/engine/install/) 20.10+ and [Docker Compose](https://docs.docker.com/compose/install/) v2+ (or [Docker Desktop](https://www.docker.com/products/docker-desktop/))

#### 2. Configure Environment (Optional for Local Dev)
```bash
# Optional: copy template to customize API keys or ports
cp .env.example .env
```
> **Security Note:** In `APP_ENV=dev` (default in Compose), the backend safely boots using development auth fallbacks without requiring secrets. For production deployments, set `APP_ENV=production` and generate a unique `JWT_SECRET` in your `.env`.

#### 3. Build & Run
```bash
# Build images and start all services in the foreground
docker compose up --build

# Or start in detached (background) mode:
docker compose up -d --build
```

#### 4. Access the Stack
| Component | URL | Description |
|---|---|---|
| **Web Dashboard** | [http://localhost:5173](http://localhost:5173) | Interactive SPA with real-time attack graph & live telemetry |
| **Backend API** | [http://localhost:8000](http://localhost:8000) | FastAPI REST endpoints |
| **API Docs (Swagger)** | [http://localhost:8000/docs](http://localhost:8000/docs) | Interactive API exploration & test runner |
| **Health Check** | [http://localhost:8000/health](http://localhost:8000/health) | Container liveness probe |

**Demo Credentials:** `analyst@acme-retail.dev` / `drishti-demo`

#### 5. Useful Docker Commands
```bash
# Follow logs for both services
docker compose logs -f

# Follow logs for backend only
docker compose logs -f server

# Run backend tests inside the running container
docker compose exec server pytest --tb=short

# Stop containers
docker compose down

# Stop containers and reset the SQLite database volume
docker compose down -v
```

#### 6. Cross-Platform & OS Notes
- **macOS (Apple Silicon M1/M2/M3/M4 & Intel):** Images use multi-arch `python:3.11-slim` and `node:22-slim` base images that compile and run natively on ARM64 and AMD64 without emulation overhead.
- **Linux (Arch, Debian, Ubuntu, Fedora):** Ensure your user belongs to the `docker` group (`sudo usermod -aG docker $USER`). Docker Compose v2 (`docker compose`) or Compose v1 (`docker-compose`) are both supported (`compose.yaml` and `docker-compose.yml` provided).
- **Windows (WSL2 / Docker Desktop):** Requires Docker Desktop running with the WSL2 backend enabled.
- **Deep Scan (nmap):** `nmap` is pre-installed in the `drishti-server` image. Because Docker bridge networks isolate the container from the physical LAN, deep scans target reachable IP addresses or subnet ranges.

---

### 💻 Option B: Manual Local Setup

### Prerequisites

- **Python 3.11+** with `uv` or `pip`
- **Node.js 18+** with `npm`
- **Redis** (optional, for caching — falls back to memory)

### Backend

```bash
# 1. Clone and enter
git clone https://github.com/Subhadip-Paul2006/dhristi.git && cd dhristi

# 2. Start the server (auto-seeds demo org on first boot)
cd server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env # adjust as needed
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Server running at **http://localhost:8000**

### Web Frontend

```bash
cd web
npm install
npm run dev
```

Web UI at **http://localhost:5173**

### Edge Agent

```bash
# Device discovery + live watch
python agent/drishti_watch.py --mode devices \
 --discover-wifi --server http://localhost:8000 \
 --token agent-demo-token

# One-shot fixture ingest (demo)
python agent/drishti_agent.py --once \
 --fixture server/app/seed/fixtures/db-prod-01.json \
 --server http://localhost:8000 \
 --token agent-demo-token
```

### Chrome Extension

1. `chrome://extensions` → toggle **Developer mode**
2. **Load unpacked** → select `extension/` folder
3. Open options → configure server URL → log in

**Demo credentials:** `analyst@acme-retail.dev` / `drishti-demo`

---

## 🛠️ Full Tech Stack

### Backend — Server

| Layer | Technology |
|---|---|
| **Framework** | FastAPI 0.115 |
| **ORM** | SQLAlchemy 2.0 + Alembic |
| **Auth** | python-jose (JWT 15m/7d) + bcrypt |
| **Graph Engine** | NetworkX 3.4 |
| **ML/Stats** | scikit-learn, numpy, scipy |
| **Scheduling** | APScheduler (deep scan) |
| **Monitoring** | prometheus-client, psutil |
| **Parsing** | beautifulsoup4, lxml, bleach |
| **CVE Data** | nvdlib (NVD API) |
| **Feeds** | feedparser, dnspython |

### Frontend — Web

| Layer | Technology |
|---|---|
| **Framework** | React 18.3 + TypeScript |
| **Build** | Vite 5 + Code Splitting |
| **Styling** | Tailwind CSS 3.4 |
| **State** | Zustand 4.5 (client) + TanStack Query 5.51 (server) |
| **Graph** | ReactFlow 11.11 (attack map) |
| **Charts** | Recharts 2.12 |
| **Animation** | Framer Motion 12.42 |
| **Icons** | Lucide React |
| **Testing** | Vitest + Testing Library |

### Edge — Agent + Extension

| Component | Stack |
|---|---|
| **Edge Agent** | Python stdlib-only (zero external deps) |
| **Chrome Extension** | Manifest V3, service worker, chrome.storage |

---

## 📁 Repository Map

```
drishti/
├── 📄 README.md ← you are here
├── ⚙️ .env.example # Environment template
├── 🐳 compose.yaml # Multi-service Docker Compose definition
├── 📦 package.json # Root (legacy web frontend)
│
├── 🖥️ server/ # FastAPI Backend
│ ├── 🐳 Dockerfile # Container definition (python:3.11-slim)
│ ├── 🐍 run.py # uvicorn entrypoint
│ ├── 📋 requirements.txt # Python deps
│ ├── 📋 pyproject.toml # Build config (hatchling)
│ ├── 🗄️ drishti.db # SQLite (dev)
│ │
│ └── 📁 app/
│ ├── 🚀 main.py # App assembly · lifespan · middleware
│ ├── ⚙️ config.py # Env-driven settings (pydantic-settings)
│ ├── 🗄️ db.py # SQLAlchemy engine + session factory
│ ├── 🔧 db_init.py # Schema column reconciliation
│ │
│ ├── 📁 api/ # 16 REST Routers
│ │ ├── health.py # Health check
│ │ ├── auth.py # JWT login / refresh / me
│ │ ├── org.py # Organization CRUD
│ │ ├── ingest.py # Agent data ingestion
│ │ ├── assets.py # Asset management
│ │ ├── findings.py # Vulnerability findings
│ │ ├── graph.py # Network graph data
│ │ ├── paths.py # Attack path computation
│ │ ├── ai.py # LLM chat + analysis
│ │ ├── dashboard.py # Exposure metrics
│ │ ├── report.py # Full org report
│ │ ├── live.py # Real-time telemetry
│ │ ├── netconfig.py # Network config export
│ │ ├── urltrust.py # URL reputation
│ │ ├── scan.py # Deep scan triggers
│ │ └── v1/ # v1 API namespace (14 routers)
│ │
│ ├── 📁 models/ # 10 SQLAlchemy ORM Models
│ │ ├── org.py # Organization + membership
│ │ ├── asset.py # Network assets
│ │ ├── vuln.py # Vulnerabilities
│ │ ├── finding.py # Risk findings
│ │ ├── path.py # Attack paths
│ │ ├── scan.py # Scan sessions
│ │ ├── remediation.py # Remediation actions
│ │ ├── live.py # Live device data
│ │ ├── netconfig.py # Network config
│ │ └── urltrust.py # URL trust entries
│ │
│ ├── 📁 schemas/ # Pydantic DTOs (12 schemas)
│ ├── 📁 services/ # 14 Business-Logic Modules
│ │ ├── risk_engine.py # NetworkX graph engine
│ │ ├── attack_paths.py # Yen's k-shortest paths
│ │ ├── impact.py # $ pricing model
│ │ ├── recompute.py # Live exposure delta
│ │ ├── ingest.py # Agent payload processing
│ │ ├── urltrust/ # URL scoring (heuristic + ML)
│ │ │ ├── analyzer.py
│ │ │ ├── checks.py
│ │ │ ├── scoring.py
│ │ │ ├── providers.py
│ │ │ ├── network.py
│ │ │ └── summary.py
│ │ ├── deepscan/ # Autonomous nmap scanner
│ │ │ ├── scanner.py
│ │ │ ├── parser.py
│ │ │ ├── cve_lookup.py
│ │ │ └── integration.py
│ │ ├── netconfig/ # Network config generation
│ │ │ ├── detectors.py
│ │ │ ├── facts.py
│ │ │ └── service.py
│ │ ├── live.py # Live watch orchestration
│ │ ├── live_threats.py # Threat feed integration
│ │ ├── autoscan.py # Scheduled deep-scan triggers
│ │ ├── hardening.py # Ansible playbook generation
│ │ ├── telegram_alerts.py # Telegram push notifications
│ │ └── ai/ # LLM integration
│ │ ├── client.py
│ │ ├── service.py
│ │ ├── prompts.py
│ │ └── ai_remediate.py
│ │
│ ├── 📁 core/ # Core Infrastructure
│ │ ├── security.py # JWT + bcrypt helpers
│ │ ├── deps.py # Auth/rate-limit dependencies
│ │ └── errors.py # Error envelope + handlers
│ │
│ ├── 📁 seed/ # Demo Data
│ │ ├── acme.py # Acme Retail demo network
│ │ └── fixtures/ # JSON scan fixtures
│ │
│ └── 📁 scripts/ # Maintenance utilities
│
├── 🌐 web/ # React SPA (Vite + TypeScript)
│ ├── src/
│ │ ├── App.tsx # Root router + providers
│ │ ├── 📁 features/ # 12 Feature Modules
│ │ │ ├── landing/ # Marketing hero page
│ │ │ ├── auth/ # Login + Signup
│ │ │ ├── dashboard/ # Exposure overview + KPIs
│ │ │ ├── graph/ # 🕸️ Attack Map (ReactFlow)
│ │ │ ├── paths/ # 🔍 Breach Simulation
│ │ │ ├── findings/ # 🚨 Severity-ranked table
│ │ │ ├── remediation/ # 🛠️ 3-Column Ansible Studio
│ │ │ ├── live/ # 📡 Force-directed live map
│ │ │ ├── report/ # 📋 Reports + NetConfig
│ │ │ ├── settings/ # ⚙️ Org settings
│ │ │ └── urltrust/ # 🌐 URL Analyzer UI
│ │ ├── 📁 api/ # TypeScript API clients
│ │ ├── 📁 store/ # Zustand state stores
│ │ ├── 📁 components/ # Shared UI components
│ │ ├── 📁 lib/ # Utilities + helpers
│ │ └── 📁 styles/ # Tailwind + global CSS
│ │
│ ├── package.json
│ ├── vite.config.ts
│ └── Dockerfile
│
├── 👁️ agent/ # Edge Agent (stdlib-only Python)
│ ├── drishti_watch.py # Live watch daemon
│ │ # (DNS/history/conn/devices modes)
│ └── drishti_agent.py # Snapshot ingester
│ # (Fixture replay + POST to /api/ingest)
│
├── 🧩 extension/ # Chrome Web Guard (MV3)
│ ├── manifest.json # MV3 manifest (minimal permissions)
│ ├── background.js # Service worker (nav gate + cache)
│ ├── options.html / .js # Server URL + login UI
│ ├── warning.html / .js / .css # Block page (redirect target)
│ └── README.md # Extension docs + demo script
│
└── 📚 Drishti Docs/ # Full Documentation Suite
 ├── PRD.md # Product Requirements
 ├── TRD.md # Technical Requirements + Formulas
 ├── ARCHITECTURE.md # C4 Diagrams + Design Decisions
 ├── APP_FLOW.md # Sequence Diagrams (All Journeys)
 ├── DATA_MODEL.md # ER Diagram + 21-Table Dictionary
 ├── API_REFERENCE.md # Every Endpoint Documented
 ├── SECURITY_MODEL.md # Defensive-Only Stance + Auth
 └── UIUX.md # Design System Specification
```

---

## 🧪 Testing

```bash
# ── Backend (232+ tests) ──
cd server
source .venv/bin/activate
pytest --tb=short -v

# ── Frontend ──
cd web
npm test

# ── Live Watch ──
python agent/drishti_watch.py --once \
 --fixture server/app/seed/fixtures/db-prod-01.json \
 --server http://localhost:8000 \
 --token agent-demo-token
```

| Test Suite | Coverage |
|---|---|
| `test_scoring.py` | Risk scoring + pricing model |
| `test_paths.py` | Attack path enumeration (Yen's) |
| `test_blast_radius.py` | Blast radius computation |
| `test_impact.py` | Dollar impact calculations |
| `test_recompute.py` | Exposure recompute pipeline |
| `test_deepscan.py` | nmap scan integration |
| `test_autoscan.py` | Scheduled scan triggers |
| `test_live.py` | Live telemetry API |
| `test_live_devices.py` | Device discovery |
| `test_agent_discovery.py` | Agent topology discovery |
| `test_agent.py` | Agent ingestion |
| `test_ingest.py` | Payload processing |
| `test_urltrust.py` | URL trust scoring |
| `test_urltrust_network.py` | URL network analysis |
| `test_auth_security.py` | JWT + bcrypt + rate limit |
| `test_accounts.py` | User + org management |
| `test_assets.py` | Asset CRUD |
| `test_contracts.py` | API contract tests |
| `test_report.py` | Report generation |
| `test_netconfig.py` | Network config export |
| `test_ai.py` | LLM integration |
| `test_config.py` | Config validation |
| `test_deps.py` | Dependency injection |
| `test_db_init.py` | Database migration |
| `test_main.py` | App startup |
| `test_live_threats.py` | Threat feed integration |
| `test_read_service.py` | Read service layer |

---

## 📊 Demo Network — Acme Retail

| Asset | Type | CVSS | Dollar Value | Status |
|---|---|---|---|---|
| `web.acme-retail.dev` | DMZ Web Server | 7.5 | **$45,000** | 🟢 Online |
| `api.acme-retail.dev` | App Server | 9.8 | **$180,000** | 🟢 Online |
| `db.acme-retail.dev` | Database (Crown Jewel) | 9.1 | **$500,000** | 🟢 Online |
| `mail.acme-retail.dev` | Mail Server | 6.1 | **$15,000** | 🟡 Degraded |
| `vpn.acme-retail.dev` | VPN Gateway | 7.8 | **$90,000** | 🟢 Online |
| `monitor.acme-retail.dev` | Monitoring | 4.3 | **$8,000** | 🟢 Online |
| **Total Exposure** | | | **$902,900** | |

Login: `analyst@acme-retail.dev` / `drishti-demo`

---

## 📚 Documentation

| Document | Description |
|---|---|
| [PRD.md](Drishti%20Docs/PRD.md) | Product Requirements — problem, personas, goals |
| [TRD.md](Drishti%20Docs/TRD.md) | Technical Requirements — stack, formulas, service specs |
| [ARCHITECTURE.md](Drishti%20Docs/ARCHITECTURE.md) | C4 diagrams, design decisions, repo map |
| [APP_FLOW.md](Drishti%20Docs/APP_FLOW.md) | Sequence diagrams for all user journeys |
| [DATA_MODEL.md](Drishti%20Docs/DATA_MODEL.md) | ER diagram, 21-table dictionary |
| [API_REFERENCE.md](Drishti%20Docs/API_REFERENCE.md) | Every endpoint (method, auth, request/response) |
| [SECURITY_MODEL.md](Drishti%20Docs/SECURITY_MODEL.md) | Defensive-only stance, consent gating, auth internals |
| [UIUX.md](Drishti%20Docs/UIUX.md) | Design system specification |

---

## 🤝 Contributing

1. Fork → `git checkout -b feat/amazing-feature`
2. Commit → `git commit -m 'feat: add amazing feature'`
3. Push → `git push origin feat/amazing-feature`
4. Open PR — all 232+ backend tests + frontend Vitest must pass

---

<div align="center">

**Drishti** &nbsp;👁️&nbsp; See the invisible. Price the risk. Fix it first.

*Defensive only. Maps, prices, and remediates. Never attacks.*

</div>
