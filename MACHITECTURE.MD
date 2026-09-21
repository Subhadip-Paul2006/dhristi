# 🏛️ Drishti: Macro & Micro-Modular Architecture (MACHITECTURE)

> **Document Version:** 1.0.0  
> **Target Release:** Drishti Enterprise v1.0 / Hackathon Championship Edition  
> **Status:** Approved & Active  
> **Architecture Pattern:** Modular Monolithic Micro-Services · Verification-First Archify Topology · Event-Driven Ingestion  
> **Repository Layout:** `server/` (FastAPI backend), `web/` (React/TS frontend), `endpoint-agent/` (cross-platform daemon), `agent/` (passive watchers), `extension/` (Chrome MV3)

---

## 1. Archify System Topology & Verified Component Boundaries

Applying the **Archify verification-first structural topology** principles ([tt-a1i/archify](https://github.com/tt-a1i/archify)), Drishti models every runtime module as a strongly bounded component with explicit communication protocols, trust boundaries, and data-flow invariants.

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1a1a2e', 'primaryTextColor': '#e0e0e0', 'primaryBorderColor': '#38c6f4', 'lineColor': '#38c6f4', 'secondaryColor': '#16213e', 'tertiaryColor': '#0f3460', 'background': '#0a0a1a', 'mainBkg': '#1a1a2e', 'nodeBorder': '#38c6f4', 'clusterBkg': '#0f3460', 'titleColor': '#e94560', 'edgeLabelBackground': '#16213e'}}}%%
flowchart TB
    subgraph BOUNDARY_CLIENT ["🛡️ TRUST BOUNDARY: Client Browser & Extension"]
        direction TB
        subgraph COMP_SPA ["Component: Drishti Web Console (SPA)"]
            SPA_UI["React 18 / Vite 5 UI Shell"]
            ZUSTAND["Zustand Stores (graphStore, liveStore, authStore)"]
            CANVAS["ReactFlow Attack Canvas & D3 ForceMap"]
            SPA_UI --> ZUSTAND --> CANVAS
        end
        subgraph COMP_EXT ["Component: Chrome Guard Extension"]
            EXT_SW["MV3 Service Worker (background.js)"]
            EXT_BLOCK["Warning Page Interceptor (warning.html)"]
            EXT_SW --> EXT_BLOCK
        end
    end

    subgraph BOUNDARY_INGRESS ["🛡️ TRUST BOUNDARY: Network Edge Gateway"]
        REVERSE_PROXY["Starlette Gateway Middleware<br/>CORS Header Validation · MaxBodySize (50MB)"]
        AUTH_GUARD["JWT Bearer & Token Version Verifier<br/>FastAPI Depends(get_current_user)"]
        REVERSE_PROXY --> AUTH_GUARD
    end

    subgraph BOUNDARY_BACKEND ["🛡️ TRUST BOUNDARY: Server Micro-Modular Core"]
        direction TB
        subgraph CORE_SERVICES ["Domain Service Modules (14 Decoupled Engines)"]
            SVC_RISK["risk_engine.py & impact.py<br/>Graph Construction & Pricing"]
            SVC_PATHS["attack_paths.py<br/>Yen's k-Shortest Paths Engine"]
            SVC_DEEPSCAN["deepscan/scanner.py<br/>Bounded Nmap Subprocess Seam"]
            SVC_VULN["vuln_intel/correlator.py<br/>Deterministic CVE & KEV Matching"]
            SVC_TRAFFIC["traffic/session_manager.py<br/>Packet Capture & Flow Aggregator"]
            SVC_AI["ml/forecasting/engine.py<br/>LSTM, GNN & Multi-Step Forecaster"]
            SVC_REMEDIATE["ai/remediation.py & hardening.py<br/>Ansible Playbooks & Cisco ACLs"]
            SVC_TELEGRAM["telegram_alerts.py<br/>Deduplicated Bot Notifier"]
        end
        subgraph ROUTERS ["API Router Facade (18 Endpoints)"]
            R_AUTH["/api/auth"]
            R_ENDPOINT["/api/endpoint"]
            R_LIVE["/api/live"]
            R_TRACKING["/api/tracking"]
            R_GRAPH["/api/graph"]
            R_PATHS["/api/paths"]
            R_AI["/api/ai"]
        end
        ROUTERS --> CORE_SERVICES
    end

    subgraph BOUNDARY_EDGE ["🛡️ TRUST BOUNDARY: Operating System Endpoints"]
        direction LR
        subgraph AGENT_CORE ["Endpoint Agent Runtime (endpoint-agent/)"]
            EP_MGR["Collector Manager & Lifecycle Engine"]
            WIN_COL["Windows Collector (Win32 / WMI)"]
            MAC_COL["macOS Collector (sysctl / libproc)"]
            EP_MGR --> WIN_COL & MAC_COL
        end
    end

    subgraph BOUNDARY_STORAGE ["🛡️ TRUST BOUNDARY: Persistent Data & Intel Layer"]
        DB[(Relational DB: SQLite / PostgreSQL<br/>21 Tables with Foreign Key Constraints)]
        REDIS_CACHE[(Redis In-Memory Cache<br/>Rate Limiting & Session State)]
        VULN_CACHE[(Local Vuln Cache<br/>NVD / CISA KEV / OSV)]
        MODEL_STORE[(PyTorch Checkpoints<br/>LSTM, Transformer, GNN, Fusion)]
    end

    SPA_UI ==>|REST / JSON over HTTPS| REVERSE_PROXY
    EXT_SW ==>|REST / Bearer over HTTPS| REVERSE_PROXY
    EP_MGR ==>|REST / Bearer over HTTPS| REVERSE_PROXY

    AUTH_GUARD --> ROUTERS
    CORE_SERVICES --> DB
    CORE_SERVICES --> REDIS_CACHE
    CORE_SERVICES --> VULN_CACHE
    CORE_SERVICES --> MODEL_STORE
    SVC_TELEGRAM -.->|Outbound HTTPS| TG_API["Telegram Bot API"]

    classDef cliStyle fill:#16213e,stroke:#38c6f4,color:#fff;
    classDef ingStyle fill:#0f3460,stroke:#f4d03f,color:#fff;
    classDef srvStyle fill:#1a1a2e,stroke:#e94560,color:#fff;
    classDef edgStyle fill:#0f3460,stroke:#00ffcc,color:#fff;
    classDef stoStyle fill:#2c1b4d,stroke:#fff,color:#fff;

    class SPA_UI,ZUSTAND,CANVAS,EXT_SW,EXT_BLOCK cliStyle;
    class REVERSE_PROXY,AUTH_GUARD ingStyle;
    class SVC_RISK,SVC_PATHS,SVC_DEEPSCAN,SVC_VULN,SVC_TRAFFIC,SVC_AI,SVC_REMEDIATE,SVC_TELEGRAM,R_AUTH,R_ENDPOINT,R_LIVE,R_TRACKING,R_GRAPH,R_PATHS,R_AI srvStyle;
    class EP_MGR,WIN_COL,MAC_COL edgStyle;
    class DB,REDIS_CACHE,VULN_CACHE,MODEL_STORE stoStyle;
```

---

## 2. Endpoint Agent Subsystem (`endpoint-agent/`)

The endpoint agent is a cross-platform daemon built with strict OS abstraction boundaries:

```mermaid
%%{init: {'theme': 'dark'}}%%
classDiagram
    class EndpointAgent {
        +Config config
        +DeviceIdentity identity
        +PairingManager pairing
        +HeartbeatManager heartbeat
        +CollectorManager collectors
        +TransportClient transport
        +start()
        +stop()
        +sync_telemetry()
    }

    class CollectorManager {
        +BaseCollector active_collector
        +get_running_processes()
        +get_listening_sockets()
        +get_installed_software()
        +get_system_services()
    }

    class WindowsCollector {
        +win32_enum_processes()
        +wmi_query_services()
        +registry_installed_software()
        +extended_tcp_table()
    }

    class MacOSCollector {
        +posix_sysctl_proc()
        +libproc_list_pids()
        +lsof_socket_inspection()
        +system_profiler_apps()
    }

    class TransportClient {
        +string agent_token
        +post_heartbeat()
        +post_telemetry()
        +request_pairing_code()
    }

    EndpointAgent *-- CollectorManager
    EndpointAgent *-- TransportClient
    CollectorManager <|-- WindowsCollector
    CollectorManager <|-- MacOSCollector
```

### Module Responsibilities
- **`endpoint-agent/agent.py`:** Core coordinator orchestrating lifecycle, exponential backoff reconnects, and periodic telemetry sweeps.
- **`endpoint-agent/common/identity.py`:** Computes immutable device identities based on machine GUID, hardware MAC, and hostname (never relies solely on volatile DHCP IPs).
- **`endpoint-agent/collectors/manager.py`:** Detects operating system (`platform.system()`) and dynamically initializes the platform-native collector.
- **`endpoint-agent/windows/collectors.py`:** Uses native Win32 APIs via `ctypes` and `winreg` to extract running user apps, Windows Services, and bound TCP ports.
- **`endpoint-agent/macos/collectors.py`:** Uses POSIX `sysctl`, `libproc`, and `lsof` to extract active macOS GUI apps (`/Applications/*`), daemons, and listening sockets.

---

## 3. Backend Micro-Modular Service Decoupling

The FastAPI server (`server/app/`) employs a clean modular monolithic architecture where routers are thin controllers delegating to 14 isolated domain services:

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    subgraph ROUTERS ["API Router Controllers"]
        R1["endpoint.py"]
        R2["tracking.py"]
        R3["graph.py"]
        R4["ai.py"]
    end

    subgraph SERVICES ["Domain Service Engines"]
        S1["endpoint_telemetry.py"]
        S2["traffic/session_manager.py"]
        S3["risk_engine.py"]
        S4["ai/remediation.py"]
        S5["vuln_intel/correlator.py"]
        S6["telegram_alerts.py"]
    end

    subgraph MODELS ["ORM Persistence Layer"]
        M1["Device & EndpointAgent"]
        M2["TrackingSession & NetworkFlow"]
        M3["Asset, Vulnerability, Finding"]
        M4["AttackPath & Remediation"]
    end

    R1 --> S1
    R2 --> S2
    R3 --> S3
    R4 --> S4

    S1 --> S5
    S2 --> S3
    S5 --> S6

    S1 --> M1
    S2 --> M2
    S3 --> M3
    S4 --> M4
```

1. **`risk_engine.py`:** Reconstructs the NetworkX `DiGraph` from SQL asset tables, executes Yen's $k$-shortest paths, and computes dollar exposures.
2. **`traffic/session_manager.py`:** Manages live packet capture threads, tracks bidirectional flows, and coordinates with `time_window.py` for feature scaling.
3. **`vuln_intel/correlator.py`:** Evaluates software versions against NVD and CISA KEV caches; enforces exact boundary checks.
4. **`telegram_alerts.py`:** Normalizes security findings into high-visibility Markdown alerts, executing deduplication fingerprints prior to dispatch.

---

## 4. Frontend Web Architecture (`web/src/`)

The user interface is an enterprise-grade React 18 single-page application engineered with a modern SOC aesthetic:

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TD
    subgraph UI_STORE ["State Management Layer (Zustand)"]
        AUTH_ST["authStore<br/>(JWT Tokens, User Profile, Org)"]
        GRAPH_ST["graphStore<br/>(Nodes, Edges, Yen's Paths, Path Filtering)"]
        LIVE_ST["liveStore<br/>(Discovered Devices, Telemetry, Active Sessions)"]
    end

    subgraph UI_VIEWS ["Feature-Sliced Module Views"]
        VIEW_DASH["DashboardPage<br/>(KPI Cards, Dollar Exposure Breakdown)"]
        VIEW_LIVE["LiveWatchPage<br/>(ForceMap, Live Activity, Device Drawer)"]
        VIEW_PATHS["AttackPathsPage<br/>(ReactFlow Canvas, Step-by-Step Breach Sim)"]
        VIEW_TRAFFIC["LiveTrafficPanel<br/>(Protocols, Real-Time AI Metrics, Forecasts)"]
    end

    subgraph UI_CANVAS ["Rendering & Visualization Engines"]
        REACTFLOW["ReactFlow Graph Renderer<br/>(Custom Dark Nodes, Animated Danger Edges)"]
        D3_FORCE["D3 Force-Directed Simulation<br/>(Live Clustered Subnet Bubbles)"]
        RECHARTS["Recharts Telemetry Graphs<br/>(Flow Rate, Packet Waterfall, Confidence)"]
    end

    AUTH_ST --> VIEW_DASH & VIEW_LIVE & VIEW_PATHS
    GRAPH_ST --> VIEW_PATHS --> REACTFLOW
    LIVE_ST --> VIEW_LIVE --> D3_FORCE
    LIVE_ST --> VIEW_TRAFFIC --> RECHARTS
```

---

## 5. Chrome Guard MV3 Extension Architecture (`extension/`)

The browser extension provides real-time client-side URL defense without compromising private user browsing data:

```mermaid
%%{init: {'theme': 'dark'}}%%
sequenceDiagram
    autonumber
    actor User as 👤 Browser User
    participant Tabs as 🌐 Chrome Tabs API
    participant Worker as 🧩 MV3 Service Worker (background.js)
    participant API as 🖥️ Drishti API (/api/urltrust)
    participant Block as 🚫 Warning Page (warning.html)

    User->>Tabs: Navigates to "http://suspicious-login.xyz"
    Tabs->>Worker: onUpdated / onCommitted tab event
    Worker->>API: POST /api/url-analyzer/analyze {url: "..."}
    API->>API: Evaluates 6-module URL trust heuristic & ML model
    alt URL is Phishing / Malicious (Score > 0.70)
        API-->>Worker: {verdict: "MALICIOUS", risk_score: 0.94, reasons: [...]}
        Worker->>Tabs: chrome.tabs.update(tabId, {url: "warning.html?target=..."})
        Tabs-->>User: Renders red screen warning blocking page load
    else URL is Clean / Benign
        API-->>Worker: {verdict: "BENIGN", risk_score: 0.05}
        Worker->>Tabs: Permits navigation; streams active tab domain to device profile
    end
```

---

## 6. End-to-End System Lifecycle & Execution Sequences

### 6.1 Complete Device Discovery, Scan, AI Track & Remediation Flow

```mermaid
%%{init: {'theme': 'dark'}}%%
sequenceDiagram
    autonumber
    actor Analyst as 👤 Analyst
    participant UI as 🌐 Web Dashboard
    participant API as 🖥️ Server API
    participant Scanner as 🔎 DeepScan (Nmap)
    participant AI as 🧠 AI Forecaster
    participant DB as 🗄️ Database

    Analyst->>UI: Clicks "Scan Device" (10.0.2.15)
    UI->>API: POST /api/scan/trigger
    API->>Scanner: Executes bounded scan
    Scanner-->>API: Ports 8000 (API), 22 (SSH) open
    API->>DB: Records services & matches CVE-2024-XXXX (CVSS 9.8)
    API->>API: Recomputes organization attack graph (Yen's paths update)
    API-->>UI: Pushes real-time graph update

    Analyst->>UI: Starts "Live Traffic Tracking"
    UI->>API: POST /api/tracking/start
    API->>API: Aggregates flows -> 27 features -> 5 sliding windows
    API->>AI: Evaluates LSTM + GNN fusion
    AI-->>API: Emits t+1, t+2, t+3 predictions (Lateral Movement risk 0.88)
    API-->>UI: Displays live MITRE T1021 alert & feature attribution

    Analyst->>UI: Clicks "Generate Fix"
    UI->>API: POST /api/ai/remediate
    API->>API: Min-Cut isolates chokepoint -> Generates Ansible playbook & Cisco ACL
    API-->>UI: Displays verified playbook in Remediation Drawer
```
