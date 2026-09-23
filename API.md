# 🔌 Drishti: REST & WebSocket API Specification

> **Document Version:** 1.0.0  
> **Base URL:** `http://127.0.0.1:8000` (Local) / `/api`  
> **Authentication:** HTTP Bearer JWT Token (`Authorization: Bearer <token>`) or HMAC Agent Token (`X-Agent-Token: <token>`)  
> **API Architecture:** FastAPI 0.115 · Starlette Routing · Pydantic v2 Type Invariants · OpenAPI 3.1 (`/docs`)

---

## Table of Contents

1. [Authentication & Agent Pairing (`/api/auth`)](#1-authentication--agent-pairing-apiauth)
2. [Dashboard Summary & Analytics (`/api/dashboard`)](#2-dashboard-summary--analytics-apidashboard)
3. [Live Telemetry & Sockets (`/api/live`)](#3-live-telemetry--sockets-apilive)
4. [Endpoint Agent Ingestion (`/api/endpoint`)](#4-endpoint-agent-ingestion-apiendpoint)
5. [Network Attack Topology Graph (`/api/graph`)](#5-network-attack-topology-graph-apigraph)
6. [Attack-Path & Chokepoint Engine (`/api/paths`)](#6-attack-path--chokepoint-engine-apipaths)
7. [Security Findings & Vulnerabilities (`/api/findings`)](#7-security-findings--vulnerabilities-apifindings)
8. [Asset Inventory & Classification (`/api/assets`)](#8-asset-inventory--classification-apiassets)
9. [AI Remediation & LLM Reasoning (`/api/ai`)](#9-ai-remediation--llm-reasoning-apiai)
10. [Passive Ingestion & PCAP Upload (`/api/ingest`)](#10-passive-ingestion--pcap-upload-apiingest)
11. [URL Trust & Phishing Intelligence (`/api/urltrust`)](#11-url-trust--phishing-intelligence-apiurltrust)
12. [Executive Reports & Export (`/api/reports`)](#12-executive-reports--export-apireports)
13. [Continuous Device Tracking (`/api/tracking`)](#13-continuous-device-tracking-apitracking)
14. [Network Subnet Configuration (`/api/netconfig`)](#14-network-subnet-configuration-apinetconfig)
15. [Organization & Crown Jewels (`/api/org`)](#15-organization--crown-jewels-apiorg)
16. [System Health & Readiness (`/api/health`)](#16-system-health--readiness-apihealth)

---

## 1. Authentication & Agent Pairing (`/api/auth`)

### `POST /api/auth/login`
Authenticates SOC analyst or administrator. Returns JSON Web Token (JWT).

- **Auth Required:** None (Public)
- **Request Body (`application/json`):**
  ```json
  {
    "username": "admin",
    "password": "change-this-in-production"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 86400,
    "user": {
      "id": "usr_01J8F2K",
      "username": "admin",
      "role": "security_admin",
      "token_version": 1
    }
  }
  ```
- **Error Cases:** `401 Unauthorized` (Invalid credentials), `429 Too Many Requests` (Rate limit exceeded).

### `POST /api/auth/register-agent`
Stage 1 of the two-stage cryptographic agent pairing ceremony.

- **Auth Required:** Bearer JWT (Admin privilege)
- **Request Body:**
  ```json
  {
    "hostname": "FIN-W11-WKSTN",
    "os_type": "windows",
    "os_version": "10.0.22631",
    "mac_address": "00:15:5D:82:11:A4",
    "internal_ip": "192.168.1.45"
  }
  ```
- **Response `201 Created`:**
  ```json
  {
    "agent_id": "agt_win_01J8K3A",
    "pairing_code": "DRS-8291-KFX",
    "pre_shared_secret": "sec_f891b2c4e8a1092b",
    "expires_at": "2026-09-23T18:00:00Z"
  }
  ```

---

## 2. Dashboard Summary & Analytics (`/api/dashboard`)

### `GET /api/dashboard/summary`
Returns top-level SOC risk posture metrics, crown jewel exposure, and active attack vectors.

- **Auth Required:** Bearer JWT
- **Response `200 OK`:**
  ```json
  {
    "total_risk_exposure_usd": 3500000.0,
    "total_assets_monitored": 28,
    "active_agents_online": 3,
    "unpaired_hosts_observed": 5,
    "critical_findings_count": 4,
    "high_findings_count": 8,
    "chokepoints_identified": 2,
    "max_cvss_observed": 10.0,
    "top_attack_path": {
      "path_id": "path_log4j_to_crown_jewel",
      "entry_node": "Edge Web Server (10.0.1.10)",
      "target_node": "Production DB Enclave (10.0.3.100)",
      "hop_count": 3,
      "risk_usd": 3500000.0
    }
  }
  ```

---

## 3. Live Telemetry & Sockets (`/api/live`)

### `GET /api/live/stream`
Server-Sent Events (SSE) or HTTP stream providing real-time socket connections bound to host PIDs.

- **Auth Required:** Bearer JWT
- **Query Parameters:** `limit` (int, default 50), `device_id` (optional string)
- **Response `200 OK` (`text/event-stream`):**
  ```text
  event: socket_update
  data: {"id": "sock_9102", "timestamp": "2026-09-23T17:30:00Z", "local_ip": "192.168.1.45", "local_port": 49812, "remote_ip": "10.0.1.10", "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED", "pid": 4112, "process_name": "chrome.exe", "user": "finance_admin"}
  ```

### `GET /api/live/packet-trace/{socket_id}`
Retrieves low-level packet capture buffer associated with an active socket flow.

- **Auth Required:** Bearer JWT
- **Response `200 OK`:**
  ```json
  {
    "socket_id": "sock_9102",
    "syn_ack_ratio": 1.02,
    "packet_count": 142,
    "byte_count": 88412,
    "entropy_score": 0.42,
    "anomaly_flag": false
  }
  ```

---

## 4. Endpoint Agent Ingestion (`/api/endpoint`)

### `POST /api/endpoint/telemetry`
High-throughput ingestion endpoint invoked by Windows, macOS, and Android daemons.

- **Auth Required:** `X-Agent-Token` header
- **Request Body:**
  ```json
  {
    "agent_id": "agt_win_01J8K3A",
    "timestamp": "2026-09-23T17:31:00Z",
    "system_metrics": {
      "cpu_percent": 14.2,
      "ram_percent": 48.5,
      "disk_free_gb": 182.4
    },
    "active_sockets": [
      {
        "local_address": "192.168.1.45:445",
        "remote_address": "10.0.1.10:38192",
        "status": "ESTABLISHED",
        "pid": 4,
        "process_name": "System"
      }
    ],
    "installed_products": [
      {
        "product_name": "Apache Tomcat",
        "version": "9.0.43",
        "install_path": "C:\\Program Files\\Apache\\Tomcat 9.0"
      }
    ]
  }
  ```
- **Response `202 Accepted`:**
  ```json
  {
    "status": "ingested",
    "findings_generated": 1,
    "next_heartbeat_seconds": 15
  }
  ```

---

## 5. Network Attack Topology Graph (`/api/graph`)

### `GET /api/graph/topology`
Generates directed graph format compatible with ReactFlow and D3 force simulation.

- **Auth Required:** Bearer JWT
- **Response `200 OK`:**
  ```json
  {
    "nodes": [
      {
        "id": "node_dmz_web",
        "label": "Edge Web Server",
        "ip": "10.0.1.10",
        "subnet": "10.0.1.0/24",
        "zone": "DMZ",
        "criticality": "HIGH",
        "exposure_usd": 420000.0,
        "is_chokepoint": false
      },
      {
        "id": "node_crown_jewel",
        "label": "Production DB Enclave",
        "ip": "10.0.3.100",
        "subnet": "10.0.3.0/24",
        "zone": "SECURE_ENCLAVE",
        "criticality": "CROWN_JEWEL",
        "exposure_usd": 3500000.0,
        "is_chokepoint": false
      }
    ],
    "edges": [
      {
        "id": "edge_web_to_corp",
        "source": "node_dmz_web",
        "target": "node_corp_wkstn",
        "protocol": "TCP/445",
        "weight": 0.85,
        "is_active_flow": true
      }
    ]
  }
  ```

---

## 6. Attack-Path & Chokepoint Engine (`/api/paths`)

### `GET /api/paths`
Enumerates lateral attack trajectories calculated by Yen's $K$-shortest paths algorithm.

- **Auth Required:** Bearer JWT
- **Response `200 OK`:**
  ```json
  [
    {
      "path_id": "path_01",
      "rank": 1,
      "cumulative_cost": 2.45,
      "risk_valuation_usd": 3500000.0,
      "hop_count": 3,
      "steps": [
        {
          "step": 1,
          "from_node": "Internet (0.0.0.0/0)",
          "to_node": "Edge Web Server (10.0.1.10)",
          "vulnerability": "CVE-2021-44228",
          "technique": "T1190 Exploit Public-Facing App"
        },
        {
          "step": 2,
          "from_node": "Edge Web Server (10.0.1.10)",
          "to_node": "Admin Workstation (192.168.1.45)",
          "vulnerability": "CVE-2017-0144",
          "technique": "T1021.002 SMB/Windows Admin Shares"
        },
        {
          "step": 3,
          "from_node": "Admin Workstation (192.168.1.45)",
          "to_node": "Production DB Enclave (10.0.3.100)",
          "vulnerability": "Stolen DB Credentials (LSASS)",
          "technique": "T1003 OS Credential Dumping"
        }
      ],
      "chokepoints": ["Internal Core Switch VLAN 30 Gate"]
    }
  ]
  ```

### `GET /api/paths/chokepoints`
Computes graph minimum-cut chokepoints where defensive intervention yields highest ROI.

- **Auth Required:** Bearer JWT
- **Response `200 OK`:**
  ```json
  [
    {
      "chokepoint_id": "chk_core_vlan_gate",
      "label": "Internal Core Switch VLAN 30 Gate",
      "paths_severed_count": 4,
      "risk_eliminated_usd": 3234000.0,
      "return_on_mitigation_pct": 92.4,
      "recommended_action": "Apply Cisco IOS ACL 101 or sever Corp-to-Enclave port 445/88"
    }
  ]
  ```

---

## 7. Security Findings & Vulnerabilities (`/api/findings`)

### `GET /api/findings`
Returns all correlated and confirmed vulnerabilities across all assets.

- **Auth Required:** Bearer JWT
- **Query Filters:** `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), `asset_id`, `cve_id`
- **Response `200 OK`:**
  ```json
  [
    {
      "id": "fnd_01J8K90",
      "asset_id": "ast_dmz_web",
      "cve_id": "CVE-2021-44228",
      "title": "Apache Log4j Remote Code Execution (Log4Shell)",
      "cvss_v3_score": 10.0,
      "severity": "CRITICAL",
      "cisa_kev_listed": true,
      "evidence_tier": "CONFIRMED",
      "detected_version": "9.0.43",
      "fixed_version": "9.0.44",
      "first_seen": "2026-09-23T17:00:00Z"
    }
  ]
  ```

---

## 8. Asset Inventory & Classification (`/api/assets`)

### `GET /api/assets`
Lists all discovered and paired network assets.

- **Auth Required:** Bearer JWT
- **Response `200 OK`:**
  ```json
  [
    {
      "id": "ast_win11_45",
      "hostname": "FIN-W11-WKSTN",
      "ip_address": "192.168.1.45",
      "mac_address": "00:15:5D:82:11:A4",
      "os_type": "windows",
      "is_paired": true,
      "agent_status": "ONLINE",
      "criticality": "HIGH",
      "open_ports": [135, 139, 445, 3389],
      "exposure_usd": 780000.0
    }
  ]
  ```

---

## 9. AI Remediation & LLM Reasoning (`/api/ai`)

### `POST /api/ai/generate-remediation`
Generates non-destructive mitigation playbooks filtered through the AST Guardrail.

- **Auth Required:** Bearer JWT
- **Request Body:**
  ```json
  {
    "path_id": "path_01",
    "target_chokepoint": "chk_core_vlan_gate",
    "format": "ansible",
    "platform": "linux"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "format": "ansible",
    "ast_guardrail_passed": true,
    "blocked_patterns_found": 0,
    "playbook_content": "---\n- name: Drishti Chokepoint Hardening\n  hosts: switches\n  tasks:\n    - name: Block Lateral SMB Ingress\n      cisco.ios.ios_acls:\n        config:\n          - name: 101\n            aces:\n              - sequence: 10\n                grant: deny\n                protocol: tcp\n                source:\n                  subnet_address: 192.168.1.0\n                  wildcard_bits: 0.0.0.255\n                destination:\n                  subnet_address: 10.0.3.0\n                  wildcard_bits: 0.0.0.255\n                destination_port:\n                  operator: eq\n                  port: 445\n",
    "human_review_required": true
  }
  ```

---

## 10. Passive Ingestion & PCAP Upload (`/api/ingest`)

### `POST /api/ingest/pcap`
Ingests a recorded `.pcap` or `.pcapng` file for offline analysis and session reconstruction.

- **Auth Required:** Bearer JWT
- **Content-Type:** `multipart/form-data`
- **Response `200 OK`:**
  ```json
  {
    "packets_processed": 8420,
    "flows_extracted": 312,
    "anomalies_detected": 2,
    "duration_seconds": 1.42
  }
  ```

---

## 11. URL Trust & Phishing Intelligence (`/api/urltrust`)

### `POST /api/urltrust/analyze`
Scores suspicious URLs using entropy, TLD risk, and Google Safe Browsing / VirusTotal APIs.

- **Auth Required:** Bearer JWT
- **Request Body:**
  ```json
  {
    "url": "http://corporate-login-secure-portal.xyz/login.php"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "url": "http://corporate-login-secure-portal.xyz/login.php",
    "risk_score": 92.5,
    "verdict": "MALICIOUS",
    "threat_category": "CREDENTIAL_PHISHING",
    "reasons": [
      "High Shannon entropy in subdomain (4.12)",
      "Newly registered domain (< 3 days)",
      "Matches brand impersonation heuristic"
    ]
  }
  ```

---

## 12. Executive Reports & Export (`/api/reports`)

### `GET /api/reports/executive`
Generates comprehensive executive summary ready for CISO and board review.

- **Auth Required:** Bearer JWT
- **Response `200 OK`:** JSON data model of the Executive Security Posture Report.

### `POST /api/reports/generate-pdf`
Compiles an audited PDF report detailing all graph paths, chokepoints, and financial risks.

- **Auth Required:** Bearer JWT
- **Response `200 OK` (`application/pdf`):** Binary PDF document stream.

---

## 13. Continuous Device Tracking (`/api/tracking`)

### `GET /api/tracking/devices`
Returns real-time online/offline heartbeat history for all paired corporate endpoints.

---

## 14. Network Subnet Configuration (`/api/netconfig`)

### `GET /api/netconfig`
Returns list of monitored CIDR ranges and subnet boundaries (e.g. `10.0.1.0/24 DMZ`, `192.168.1.0/24 Corp`).

---

## 15. Organization & Crown Jewels (`/api/org`)

### `GET /api/org/crown-jewels`
Retrieves designated high-value business assets and their financial valuations.

- **Response `200 OK`:**
  ```json
  [
    {
      "id": "cj_01",
      "name": "Production Database Enclave",
      "ip": "10.0.3.100",
      "asset_valuation_usd": 3500000.0,
      "data_classification": "RESTRICTED_PII_FINANCIAL"
    }
  ]
  ```

---

## 16. System Health & Readiness (`/api/health`)

### `GET /api/health/live`
Kubernetes / Docker liveness probe. Returns `{"status": "alive"}`.

### `GET /api/health/ready`
Readiness probe checking database connectivity, graph engine state, and model artifacts.

- **Response `200 OK`:**
  ```json
  {
    "status": "ready",
    "database_connected": true,
    "graph_engine_initialized": true,
    "ai_models_loaded": true,
    "uptime_seconds": 18420
  }
  ```
