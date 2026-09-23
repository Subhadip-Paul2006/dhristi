# 📖 Drishti: User & Evaluator Operational Guide

> **Target Audience:** Security Analysts, Hackathon Evaluators, VAPT Professionals, System Administrators  
> **Platform Version:** Drishti Enterprise v1.0 / Championship Edition  
> **Interface:** Web SOC Console (`http://localhost:5173`) · Vercel Standalone Preview

---

## Table of Contents

1. [Quick-Start Evaluation (Under 3 Minutes)](#1-quick-start-evaluation-under-3-minutes)
2. [Authentication & Demo Mode Toggle](#2-authentication--demo-mode-toggle)
3. [SOC Posture Dashboard](#3-soc-posture-dashboard)
4. [Interactive Attack Map (Graph Canvas)](#4-interactive-attack-map-graph-canvas)
5. [Live Watch: Real-Time Sockets & Packet Flows](#5-live-watch-real-time-sockets--packet-flows)
6. [Attack Path Analysis & Yen's $K$-Shortest Paths](#6-attack-path-analysis--yens-k-shortest-paths)
7. [Vulnerability Findings & Evidence Matrix](#7-vulnerability-findings--evidence-matrix)
8. [Asset Inventory & Platform Agents](#8-asset-inventory--platform-agents)
9. [AI Remediation & Safe Playbook Generation](#9-ai-remediation--safe-playbook-generation)
10. [Executive Report & PDF Export](#10-executive-report--pdf-export)
11. [URL Trust & Phishing Intelligence](#11-url-trust--phishing-intelligence)

---

## 1. Quick-Start Evaluation (Under 3 Minutes)

Drishti provides two evaluation modalities:

1. **Standalone Web Preview (Zero Backend Required):**
   - Ideal for rapid visual evaluation and UI inspection.
   - Hosted on Vercel with `VITE_DEMO_MODE=true`.
   - Uses deterministic, synthetic enterprise telemetry.
2. **Local Full-Stack Deployment:**
   - Full end-to-end operation with FastAPI backend, live packet sniffing, and cross-platform endpoint agents.
   - Run according to [SETUP.md](SETUP.md).

---

## 2. Authentication & Demo Mode Toggle

![Drishti Login Screen](assets/screenshots/01-login.png)

1. Navigate to `http://localhost:5173/login` in your web browser.
2. **Default Evaluator Credentials:**
   - **Username:** `admin`
   - **Password:** `admin` (or any string in Demo Mode)
3. **Demo Mode Notification:**
   - When running without a local backend, the login screen displays a distinct yellow banner:
     `Demo Mode Active: Running with synthetic offline telemetry. No backend required.`
4. Click **Sign In to Console**. The authentication state persists in session storage with a valid token mock.

---

## 3. SOC Posture Dashboard

![Drishti SOC Posture Dashboard](assets/screenshots/02-dashboard.png)

Upon authentication, the **Enterprise Threat Posture** dashboard loads:

- **Cumulative Dollar Risk Exposure:** Top-left metric displaying total financial exposure (e.g. **$3,500,000 USD**) if all active breach paths to crown jewels succeed.
- **Critical & High Findings:** Count of active vulnerabilities filtered by CVSS severity and CISA KEV status.
- **Top Attack Vector:** Directly highlights the most urgent lateral attack path (e.g. Log4j on Edge Web Server traversing to Production DB).
- **Risk Timeline:** Real-time chart tracking organizational risk index variations over the last 24 hours.

---

## 4. Interactive Attack Map (Graph Canvas)

![Drishti Attack Map Graph](assets/screenshots/03-attack-map.png)

Click **Attack Map** in the left navigation sidebar:

1. **Directed Attack Graph:** Rendered using ReactFlow with custom cyber-themed nodes:
   - **Red Nodes:** Entrypoints and high-risk compromised assets.
   - **Amber Nodes:** Lateral pivot workstations.
   - **Yellow Nodes:** Identity providers (Active Directory Domain Controllers).
   - **Emerald Green Nodes:** Corporate Crown Jewels (Financial database enclave).
2. **Pulsing Chokepoints:** Nodes identified by the graph Min-Cut algorithm pulse with a purple ring, indicating strategic intervention targets.
3. **Node Drill-down:** Click any node to open the side inspector panel showing IP address, operating system, open listening ports, and detected software versions.

---

## 5. Live Watch: Real-Time Sockets & Packet Flows

![Drishti Live Watch Grid](assets/screenshots/04-live-watch.png)

Click **Live Watch** in the navigation menu:

- **Unified Socket-to-PID Grid:** Correlates network connections with the specific executable process and CPU/RAM usage on the endpoint:
  ```text
  192.168.1.45:49812 <--> 104.244.42.1:443 | TCP | ESTABLISHED | PID 4112 [chrome.exe] | User: admin
  ```
- **Packet Sniffer Integration:** Displays packet counters, SYN/ACK ratios, and flow entropy.
- **One-Click Packet Trace:** Click **Inspect Trace** on any connection to view the underlying packet decapsulation view (Layer 2 through Layer 7).

---

## 6. Attack Path Analysis & Yen's $K$-Shortest Paths

![Drishti Attack Paths View](assets/screenshots/05-attack-paths.png)

Click **Attack Paths** in the navigation menu:

1. **Ranked Breach Routes:** Displays paths calculated by Yen's $K$-shortest paths algorithm over the topology graph.
2. **Path Valuation:** Every path has a dollar valuation calculated via:
   $$\text{Path Risk} = \text{Target Valuation} \times \prod_{i} P(\text{compromise}_i)$$
3. **Chokepoint Severance:** Inspect the **Recommended Intervention** box to see how severing a single choke point eliminates multiple lateral hops simultaneously.

---

## 7. Vulnerability Findings & Evidence Matrix

![Drishti Findings Table](assets/screenshots/06-findings.png)

Click **Findings** to view the vulnerability catalog:

- **Evidence Tier Filter:** Filter findings by evidentiary certainty:
  - `OBSERVED`: Raw port or process seen.
  - `CORRELATED`: Matched to known software product/CPE.
  - `POTENTIAL`: CVE exists; exact version pending.
  - `CONFIRMED`: Exact version verified within `[affected_start, fixed_version)`.
- **CISA KEV Badges:** Any vulnerability listed in the CISA Known Exploited Vulnerabilities catalog receives an emergency priority flag.

---

## 8. Asset Inventory & Platform Agents

![Drishti Asset Inventory](assets/screenshots/07-assets.png)

Click **Assets** to inspect managed hosts:

- View paired Windows workstations, macOS laptops, and Android mobile devices.
- Review OS version, MAC address, assigned subnet, and agent daemon heartbeat state (`ONLINE`, `STALE`, `OFFLINE`).
- Inspect unpaired hosts detected passively via ARP and mDNS broadcasts.

---

## 9. AI Remediation & Safe Playbook Generation

From either the **Attack Paths** or **Findings** page:

1. Click **Generate Mitigation Playbook**.
2. Select target format:
   - **Ansible Playbook (`.yml`)**
   - **Cisco IOS ACL Rules**
   - **PowerShell / Bash Hardening Script**
3. **AST Guardrail Validation:**
   - The platform routes the prompt through Anthropic Claude 3.5 Sonnet.
   - The resulting script is parsed via Python's `ast.parse()` to guarantee zero destructive commands (`rm`, `dd`, `mkfs`, `iptables -F`, etc.).
   - The verified playbook appears in a syntax-highlighted code editor with a **Copy to Clipboard** button.

---

## 10. Executive Report & PDF Export

![Drishti Executive Report](assets/screenshots/08-executive-report.png)

Click **Executive Report** in the navigation menu:

- **Board-Level Posture Summary:** Formatted for C-suite and risk management executives.
- **Return on Mitigation (ROM):** Displays the exact dollar savings achieved if the recommended choke points are hardened.
- **Export Options:** Click **Export PDF** or **Export JSON** to generate an audited compliance record.

---

## 11. URL Trust & Phishing Intelligence

![Drishti URL Trust Analyzer](assets/screenshots/09-url-analyzer.png)

Click **URL Analyzer** in the navigation menu:

1. Paste any external or internal URL (e.g. `http://suspicious-internal-login.test`).
2. Drishti computes:
   - Shannon entropy score of the domain.
   - Domain age and TLD risk factor.
   - Safe Browsing / VirusTotal correlation.
3. Generates a clear verdict: `BENIGN`, `SUSPICIOUS`, or `MALICIOUS PHISHING`.
