# DRISHTI — ENDPOINT AGENT + DEVICE INTELLIGENCE
# FINAL PHASES / IMPLEMENTATION ROADMAP
## Windows + macOS | Authorized Lab Only | Zero Fabrication | Existing System Preserved

---

# 0. PURPOSE

This document defines the final implementation roadmap for the Drishti
Endpoint Agent and its integration with the existing Drishti platform.

The objective is to add endpoint-level visibility and security intelligence
WITHOUT breaking, replacing, redesigning, or silently changing anything that
already works.

The existing Drishti system already contains:

- LAN device discovery
- device presence/session history
- Device Scan / DeepScan
- open-port and service detection
- CVE correlation
- existing vulnerability findings
- existing Generate Fix workflow
- dark/black SOC UI
- Live Network Traffic Tracking
- network evidence/timeline
- live flow aggregation
- canonical traffic features
- LSTM detection
- Transformer detection
- GNN detection
- fusion/detection infrastructure
- future forecasting architecture
- browser-extension architecture
- existing maps/topology

This roadmap adds endpoint intelligence as a complementary layer.

It is NOT a replacement for the existing network scanner or AI pipeline.

---

# 1. ABSOLUTE NON-NEGOTIABLE RULES

## 1.1 Existing functionality is frozen

The following MUST continue working:

- Existing dark/black UI theme
- Existing dashboard layout
- Existing device cards
- Existing Device Detail drawer
- Existing device discovery
- Existing network map/topology
- Existing attack map
- Existing DeepScan / Device Scan
- Existing Nmap integration
- Existing CVE lookup/correlation
- Existing risk display
- Existing Generate Fix feature
- Existing Live Network Traffic Tracking
- Existing network evidence/timeline
- Existing LSTM implementation
- Existing Transformer implementation
- Existing GNN implementation
- Existing forecasting implementation
- Existing browser extension functionality
- Existing authentication and authorization contracts
- Existing API contracts unless an additive extension is strictly required

Never rewrite working modules merely to make the new agent fit.

---

## 1.2 GitHub is completely untouched

The implementation MUST remain local unless the user explicitly requests
otherwise.

Forbidden:

- git push
- git commit
- git reset
- git rebase
- force push
- branch deletion
- remote changes
- GitHub PR creation
- GitHub Action modifications
- `.github/` modifications

Before every major phase:

```text
git status
git diff --stat
```

At the end:

```text
GITHUB: UNTOUCHED
```

---

## 1.3 Zero fabrication

Drishti MUST NOT invent:

- running applications
- background processes
- services
- software
- software versions
- browser tabs
- network traffic
- open ports
- domains
- CVEs
- vulnerabilities
- attack events
- forecast probabilities
- remediation claims
- Telegram alerts

Every displayed result must retain an evidence source.

---

## 1.4 Evidence hierarchy

The system must distinguish:

```text
OBSERVED
  ↓
CORRELATED
  ↓
POTENTIAL
  ↓
CONFIRMED
```

Do not collapse these states.

Examples:

```text
Process observed
≠
Website observed

Open port observed
≠
Vulnerability confirmed

CVE exists
≠
Device is vulnerable

Prediction generated
≠
Attack confirmed

Network destination observed
≠
Browser tab confirmed
```

---

# 2. FINAL DRISHTI ARCHITECTURE

```text
                         DRISHTI
                            │
           ┌────────────────┼────────────────┐
           │                │                │
           ▼                ▼                ▼
     NETWORK LAYER     ENDPOINT LAYER    BROWSER LAYER
           │                │                │
     LAN Discovery      Agent Service     Browser Extension
     ARP / ICMP         Processes         Active Tabs
     Nmap               Applications      URL / Domain / Title
     Services           Services
     Versions           Software
     Ports              OS
     Traffic            Sockets
     DNS                VPN
           │                │                │
           └────────────────┼────────────────┘
                            ▼
                    DEVICE IDENTITY
                            │
                            ▼
                  DEVICE SECURITY PROFILE
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
       VULNERABILITY    NETWORK AI      RISK ENGINE
        CORRELATOR       PIPELINE            │
             │              │               │
      NVD / CISA KEV   LSTM / Transformer   │
      OSV / GHSA       GNN / Fusion         │
             │              │               │
             └──────────────┼───────────────┘
                            ▼
                     SECURITY FINDINGS
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
        DASHBOARD      GENERATE FIX     TELEGRAM
```

---

# 3. DATA FLOW PRINCIPLE

Every endpoint follows:

```text
INSTALL / START AGENT
        ↓
PAIR DEVICE
        ↓
REGISTER DEVICE
        ↓
HEARTBEAT
        ↓
COLLECT TELEMETRY
        ↓
SEND AUTHENTICATED TELEMETRY
        ↓
DEVICE-SCOPED STORAGE
        ↓
CORRELATION ENGINE
        ↓
SECURITY FINDINGS
        ↓
DASHBOARD / ALERTS
```

The agent MUST NOT be responsible for:

- dashboard rendering
- vulnerability database synchronization
- final risk scoring
- Telegram message formatting
- AI forecasting decisions

Those belong to backend services.

---

# 4. DEVICE ENROLLMENT MODEL

The final UX should be:

```text
REMOTE DEVICE
     ↓
Install / run Drishti Agent
     ↓
Agent displays one-time Pairing Code
     ↓
Drishti Dashboard
     ↓
Pair Endpoint Agent
     ↓
Enter Pairing Code
     ↓
PAIRING VERIFIED
     ↓
AGENT REGISTERED
     ↓
DEVICE CONNECTED
```

The operator should NOT manually enter backend bearer tokens into the
browser extension.

The endpoint agent should receive/derive the credentials required for its
own authenticated backend communication.

---

# 5. PHASE 01 — ENDPOINT AGENT FOUNDATION
## Goal: Agent lifecycle + pairing + secure communication

### 5.1 Objectives

Build a small endpoint component that can be installed/run on an authorized:

- Windows workstation
- macOS workstation

The agent must:

- start
- identify itself
- display pairing code
- register after pairing
- authenticate with the backend
- heartbeat periodically
- reconnect after temporary network failure
- expose a local health/status state
- shut down cleanly

### 5.2 Agent Architecture

```text
Drishti Endpoint Agent
│
├── Bootstrap
├── Device Identity
├── Pairing Manager
├── Authentication
├── Heartbeat Manager
├── Collector Manager
├── Local Cache
└── Backend Transport
```

### 5.3 Device Identity

Register:

- agent_id
- device_id
- hostname
- OS
- OS version
- hardware MAC where available
- current IP
- agent version
- registration timestamp
- last heartbeat

Identity MUST NOT depend only on IP address.

### 5.4 Pairing

Pairing must use a short-lived one-time code.

Example:

```text
DRISHTI PAIRING CODE

AB7X-92KF
Expires in 5 minutes
```

Requirements:

- one-time use
- expiration
- invalid-code rejection
- reused-code rejection
- auditable registration event

### 5.5 Backend Transport

Use the existing backend communication architecture where possible.

The agent must use authenticated requests.

Do not expose long-lived secrets in:

- browser extension source
- frontend JavaScript
- public configuration
- logs

Use TLS when supported by deployment.

### 5.6 Heartbeat

Default heartbeat:

```text
30–60 seconds
```

Heartbeat includes:

- agent_id
- device_id
- timestamp
- agent version
- collector health
- backend connectivity status

Backend derives:

```text
ONLINE
STALE
OFFLINE
```

### 5.7 Testing

Unit tests:

- identity generation
- identity persistence
- pairing-code generation
- pairing expiration
- pairing success
- pairing rejection
- authentication failure
- heartbeat success
- heartbeat timeout
- reconnect
- graceful shutdown

Integration:

```text
Agent → Pair → Backend → Device Registered
```

Negative tests:

- invalid pairing code
- expired pairing code
- duplicate pairing
- invalid token
- wrong organization
- malformed request

Acceptance:

```text
[ ] Windows agent starts
[ ] macOS agent starts
[ ] Pairing works
[ ] Device appears in dashboard
[ ] Heartbeat works
[ ] Offline state works
[ ] Reconnect works
```

---

# 6. PHASE 02 — ENDPOINT TELEMETRY
## Goal: Processes + Applications + Services + Software + Ports

This phase addresses the current remote-device endpoint telemetry gap.

### 6.1 Windows Collector

Create OS-specific collectors behind a common interface:

```text
EndpointCollector
     │
     ├── WindowsCollector
     └── MacOSCollector
```

Windows collector should gather, where permitted:

- process name
- PID
- PPID
- start time
- executable path
- category
- observation time

Categories:

```text
USER_APPLICATION
BACKGROUND_PROCESS
SYSTEM_PROCESS
```

### 6.2 Running Applications

Running applications MUST come from actual process observation.

Examples:

```text
VS Code
Chrome
Arc
Node
Python
Docker
Terminal
Discord
```

Only show what is actually observed.

Never use installed software as proof that software is currently running.

### 6.3 Background Processes

Collect meaningful user-space background processes and system services.

Keep category and evidence source.

### 6.4 Installed Software

Collect read-only software inventory:

- name
- version
- publisher
- install location where appropriate
- source/category where available

Keep installed software separate from running software.

### 6.5 Services

Collect local services where OS APIs permit.

For each:

- name
- display name
- status
- startup type where available
- version where available
- observed timestamp

Do not automatically label every service dangerous.

### 6.6 Listening / Open Local Ports

Where permissions allow, enumerate locally listening sockets.

Example:

```text
0.0.0.0:3000 → LISTENING
0.0.0.0:5432 → LISTENING
127.0.0.1:8000 → LISTENING
```

Where possible:

```text
PID → Process → Local socket
```

### 6.7 Process → Network Socket

Collect where permissions allow:

- PID
- process
- protocol
- local endpoint
- remote endpoint
- state
- observed timestamp

Do not translate remote IP into a website automatically.

### 6.8 Browser Process Inventory

The endpoint agent may report browser processes:

```text
Chrome running
Edge running
Brave running
Arc running
Firefox running
```

Actual open-tab URLs/titles remain browser-extension telemetry.

### 6.9 macOS Collector

Implement equivalent read-only collectors for:

- processes
- applications
- services/daemons
- listening sockets
- network connections
- installed software
- OS information

Use a common data contract.

Missing data must be represented as:

```text
UNAVAILABLE
```

rather than fabricated.

### 6.10 Telemetry TTL

Recommended:

```text
Process data: 60s
Services: 60s
Socket data: 60s
Software inventory: 5–15m
OS metadata: 5–15m
Heartbeat: 30–60s
```

All TTL values must be configurable.

### 6.11 Phase 02 Testing

Windows:
- process enumeration
- application categorization
- background process visibility
- service enumeration
- software inventory
- listening port enumeration
- socket correlation
- PID correctness
- process start/stop
- stale telemetry

macOS:
- process enumeration
- application enumeration
- service/daemon enumeration where permitted
- socket enumeration
- software inventory
- permission failures
- stale telemetry

Cross-device:

```text
Device A telemetry → A
Device B telemetry → B
```

No cross-device leakage.

---

# 7. PHASE 03 — VULNERABILITY INTELLIGENCE
## Goal: Endpoint + Network evidence → CVE/KEV/OSV/GHSA findings

This phase connects endpoint inventory with the existing vulnerability engine.
It MUST NOT replace the existing Device Scan.

### 7.1 Data Sources

```text
NVD / CVE
CISA KEV
OSV
GitHub Security Advisories / GHSA
```

Use each source according to its actual scope.

### 7.2 Local Vulnerability Cache

Architecture:

```text
External Sources
      ↓
Sync Worker
      ↓
Local Vulnerability Cache
      ↓
Correlation Engine
```

Store:

- identifier
- aliases
- vendor
- product
- package
- ecosystem
- affected versions
- fixed versions
- CVSS
- severity
- published date
- modified date
- KEV status
- references
- source

### 7.3 Product / Version Correlation

```text
Observed Product
      ↓
Vendor/Product Identity
      ↓
CPE or package identity
      ↓
Version range
      ↓
NVD / OSV / GHSA
      ↓
CVE/Advisory Match
```

Respect affected and fixed version boundaries.

Never mark every version of a product vulnerable.

### 7.4 CISA KEV Enrichment

After a reliable CVE match:

```text
CVE
 ↓
KEV?
 ↓
YES / NO
```

Display:

```text
VULNERABLE
KNOWN EXPLOITED
```

separately.

### 7.5 Finding States

Use:

```text
OPEN
EXPOSED
POTENTIAL_MATCH
VULNERABLE
KNOWN_EXPLOITED
NO_CONFIRMED_VULNERABILITY
```

### 7.6 Testing

Test:

- exact product match
- version range match
- fixed-version exclusion
- CPE match
- package/ecosystem match
- NVD match
- OSV match
- GHSA match
- KEV enrichment
- no-match
- unknown-version
- duplicate aliases
- no fabricated CVEs

Existing Device Scan MUST remain functional.

---

# 8. PHASE 04 — ENDPOINT + NETWORK + AI INTEGRATION
## Goal: Unified device security profile using existing systems

### 8.1 Unified Device Security Profile

```text
DEVICE
│
├── Identity
├── Presence
│
├── Network Scan
│   ├── Open Ports
│   ├── Services
│   └── Versions
│
├── Endpoint
│   ├── Applications
│   ├── Processes
│   ├── Services
│   ├── Software
│   └── Sockets
│
├── Browser
│   └── Active Tabs
│
├── Network Traffic
│   ├── DNS
│   ├── Flows
│   └── Destinations
│
├── Vulnerabilities
│
└── AI Security State
    ├── Current Detection
    └── Future Forecast
```

### 8.2 AI Integration

Reuse existing:

```text
Traffic
 ↓
Flow
 ↓
Feature Extraction
 ↓
Time Windows
 ↓
LSTM
 ↓
Transformer
 ↓
GNN
 ↓
Fusion
 ↓
Detection
 ↓
Forecast
```

Endpoint telemetry is contextual enrichment unless explicitly included in a
trained model.

### 8.3 Device-Specific AI State

```text
Device A
→ history A
→ graph A
→ detection A
→ forecast A

Device B
→ history B
→ graph B
→ detection B
→ forecast B
```

No global/shared device state for independent predictions.

### 8.4 Integration Testing

Test:

- endpoint identity + network identity
- software + CVE
- process + socket
- traffic + device
- detection + device
- forecast + device
- endpoint/network isolation
- stale endpoint + live network state

---

# 9. PHASE 05 — REMEDIATION + TELEGRAM ALERTS
## Goal: Evidence-backed fix generation and notifications

This phase finally connects findings to:

1. Existing Generate Fix
2. Telegram Bot Notifications

## 9.1 Existing Generate Fix Audit

Before changing remediation, inspect exactly how the current system performs:

```text
Finding
 ↓
finding_id
 ↓
POST /api/ai/remediate
 ↓
Existing AI service / prompt template
 ↓
Generated Fix
 ↓
RemediationConsole
```

Document:

- frontend component
- backend route
- service
- prompt/template
- model/provider
- request schema
- response schema
- validation
- existing safety checks

Do not duplicate the existing remediation architecture.

## 9.2 Network Finding → Existing Generate Fix

```text
Network / Endpoint Finding
       ↓
Affected Device
       ↓
Affected Port / Service / Software
       ↓
Evidence
       ↓
Existing Remediation Service
       ↓
Finding-specific fix guidance
```

The remediation generator must use only verified finding data.

Never invent:

- software versions
- CVEs
- configuration
- installed software
- device state

## 9.3 Remediation Output States

Use:

```text
REMEDIATION_AVAILABLE
REMEDIATION_REQUIRES_REVIEW
REMEDIATION_UNAVAILABLE
```

Recommended wording:

```text
Suggested Fix
```

until actual execution and verification exist.

## 9.4 Telegram Notification Architecture

```text
Security Finding
      ↓
Alert Normalizer
      ↓
Notification Policy
      ↓
Telegram Adapter
      ↓
Telegram Bot
      ↓
Authorized Chat
```

Telegram is a notification channel, not a source of truth.

## 9.5 Telegram Secrets

Never put the Telegram bot token in:

- frontend JavaScript
- browser extension
- GitHub
- committed config
- logs

Use backend/server-side environment configuration.

Example:

```text
TELEGRAM_BOT_TOKEN=<server-side-secret>
TELEGRAM_CHAT_ID=<authorized-chat-id>
```

Never print these values in logs.

## 9.6 Telegram Message

Example:

```text
🚨 DRISHTI SECURITY ALERT

Device: WORKSTATION-02
IP: 192.168.1.20

Finding:
Known vulnerable service

CVE:
CVE-XXXX-XXXX

Severity:
HIGH

Evidence:
Service: ExampleService
Version: X.Y.Z
Port: 443/TCP

KEV:
YES

Status:
REQUIRES REVIEW
```

Every claim must be directly supported by the finding record.

Missing values must say:

```text
Not available
```

## 9.7 Telegram Alert Policy

Avoid notification spam.

Generate a fingerprint such as:

```text
device_id
+
finding_id / CVE
+
observed_version
+
severity
```

Possible triggers:

- new vulnerability
- severity increase
- KEV status added
- new exposed service
- high-confidence detection
- high-risk forecast

Only if supported by actual evidence/state.

## 9.8 Telegram Testing

Unit tests:

- message formatting
- missing field handling
- severity rendering
- CVE formatting
- KEV formatting
- duplicate fingerprinting
- deduplication
- retry
- timeout
- Telegram API failure
- invalid token handling

Integration:

```text
Finding → Alert Normalizer → Telegram Adapter → Telegram API mock
```

Automated tests MUST NOT use the real production bot token.

Manual:

```text
Real authorized finding
↓
One Telegram notification

Repeat same finding
↓
No duplicate spam

Finding state changes
↓
New notification
```

---

# 10. BROWSER EXTENSION INTEGRATION

The existing browser extension remains an endpoint companion rather than a
replacement for the agent.

Supported targets may include:

- Chrome
- Edge
- Brave
- Arc where supported
- Firefox where technically compatible

The extension should report only approved metadata:

- browser
- currently open/active tab
- title
- URL
- domain
- timestamp

The browser extension MUST NOT collect:

- passwords
- cookies
- authentication tokens
- private messages
- page DOM
- form data
- keystrokes
- clipboard
- browser history unless explicitly authorized as a separate feature

The extension communicates through the existing local agent bridge where
applicable.

---

# 11. DEVICE SCAN VS ENDPOINT TELEMETRY

These remain separate.

## Device Scan

```text
Selected Device
      ↓
Network-level scan
      ↓
Open Ports
      ↓
Services
      ↓
Versions
      ↓
CVE Correlation
      ↓
Device Findings
```

Endpoint Agent is NOT required simply to perform network-level Device Scan.

## Endpoint Telemetry

```text
Selected Device
      ↓
Endpoint Agent
      ↓
Processes
Applications
Services
Software
Sockets
OS
```

## Browser Telemetry

```text
Browser
      ↓
Extension
      ↓
Active Tabs
```

Do not turn absence of the endpoint agent into a failed network scan.

---

# 12. LIVE NETWORK TRAFFIC + AI

The existing network traffic architecture remains:

```text
LIVE NETWORK
      ↓
CAPTURE
      ↓
FLOW
      ↓
FEATURES
      ↓
TIME WINDOWS
      ↓
LSTM
Transformer
GNN
      ↓
FUSION
      ↓
CURRENT DETECTION
      ↓
FUTURE FORECAST
      ↓
RISK
```

Traffic visibility must remain truthful.

If the monitoring interface cannot observe another device's unicast traffic,
show:

```text
TRAFFIC VISIBILITY UNAVAILABLE
```

or:

```text
LIMITED VISIBILITY
```

Do not interpret zero captured packets as proof that a device has zero traffic.

---

# 13. DATA STORAGE & BOUNDARIES

Use device-scoped records.

Suggested conceptual entities:

```text
devices
endpoint_agents
endpoint_heartbeats
software_inventory
running_processes
endpoint_services
network_sockets
browser_tabs
tracking_sessions
network_events
network_flows
network_timelines
vulnerabilities
vulnerability_aliases
device_findings
notifications
```

Never allow unlimited live-memory accumulation.

Use:

- TTL
- bounded queues
- bounded caches
- retention policies
- cleanup workers

---

# 14. NO-HALLUCINATION / EVIDENCE CONTRACT

Every security statement must be traceable:

```text
UI Claim
 ↓
Finding / Result
 ↓
Evidence
 ↓
Source
 ↓
Observed Time
```

Examples:

```text
"Port 445 OPEN"
→ Nmap evidence
→ scan timestamp
```

```text
"VS Code X.Y.Z affected by CVE-XXXX"
→ endpoint software inventory
→ observed version
→ vulnerability record
→ deterministic correlation
```

```text
"Likely reconnaissance continuation"
→ forecasting model
→ actual temporal sequence
→ actual model output
```

Do not create generic reasoning that is not connected to evidence.

---

# 15. CROSS-DEVICE ISOLATION

At every layer:

```text
Device A
 ├── telemetry A
 ├── network A
 ├── findings A
 └── alerts A

Device B
 ├── telemetry B
 ├── network B
 ├── findings B
 └── alerts B
```

A's data must never appear under B.

Test isolation independently at:

- agent
- API
- database
- network flow
- AI state
- findings
- Telegram alerts

---

# 16. TESTING STRATEGY

Every feature must be tested at four levels.

## A. Unit

Individual functions/classes.

## B. Integration

Module-to-module behavior.

Examples:

```text
Agent → Backend
Scanner → CVE Engine
Finding → Telegram
```

## C. E2E

Real workflow:

```text
Install Agent
↓
Pair
↓
Heartbeat
↓
Telemetry
↓
Scan
↓
Finding
↓
Dashboard
↓
Telegram
```

## D. Negative / Failure

Test:

- permission denied
- missing dependency
- offline endpoint
- invalid identity
- expired pairing
- malformed telemetry
- capture unavailable
- API timeout
- vulnerability source unavailable
- Telegram unavailable
- model unavailable
- stale data

Every failure must be truthful.

---

# 17. WINDOWS TESTING

Test at least:

### Windows Device A

- agent installation/start
- pairing
- processes
- background processes
- services
- software
- versions
- listening ports
- sockets
- browser process
- browser extension
- active tabs
- Device Scan
- vulnerability correlation
- dashboard
- Telegram

### Windows Device B

Repeat independently.

Then verify:

```text
A telemetry → A
B telemetry → B
```

---

# 18. macOS TESTING

On an authorized Mac:

- agent install
- required OS permissions
- pairing
- heartbeat
- processes
- applications
- services/daemons where permitted
- software
- sockets
- browser process
- browser extension where supported
- Device Scan from Drishti
- vulnerability correlation

Any macOS permission limitation must be shown explicitly.

---

# 19. PACKAGING

Keep one endpoint-agent codebase:

```text
endpoint-agent/
│
├── common/
├── windows/
├── macos/
├── transport/
├── collectors/
└── packaging/
```

Build:

```text
Windows → Drishti-Agent.exe
macOS   → Drishti-Agent.pkg
```

For the first working MVP, a portable/dev execution path may exist before
installer packaging.

Packaging is a delivery mechanism, not a separate agent architecture.

---

# 20. FINAL DEPLOYMENT WORKFLOW

## On Windows/Mac target

```text
Receive Agent
     ↓
Install / Run
     ↓
Pairing Code
     ↓
Operator enters code in Dashboard
     ↓
Paired
     ↓
Agent heartbeat
     ↓
Endpoint telemetry
```

The target user should NOT need the entire Drishti source tree.

They receive the endpoint agent package appropriate for their OS.

---

# 21. FINAL HACKATHON DEMO FLOW

```text
LAN DISCOVERY
      ↓
Select Device
      ↓
DEVICE DETAIL
      │
      ├── Scan Device
      │        ↓
      │   Ports / Services / Versions
      │        ↓
      │   NVD / KEV / OSV / GHSA
      │
      ├── Track Live Network Traffic
      │        ↓
      │   Capture → Flow → Features
      │        ↓
      │   LSTM / Transformer / GNN
      │        ↓
      │   Detection / Forecast
      │
      └── Pair Endpoint Agent
               ↓
         Processes / Apps
         Services / Software
         Sockets / OS
               ↓
        Unified Device Profile
               ↓
          Security Finding
             ├── Dashboard
             ├── Generate Fix
             └── Telegram
```

---

# 22. FINAL ACCEPTANCE CHECKLIST

## Endpoint

[ ] Windows agent starts
[ ] macOS agent starts
[ ] Device identity works
[ ] Pairing works
[ ] Heartbeat works
[ ] Reconnect works
[ ] Offline state works

## Endpoint Telemetry

[ ] Running applications are real
[ ] Background processes are real
[ ] Services are real
[ ] Installed software is real
[ ] Versions are real where available
[ ] Listening ports are real
[ ] Process/socket relationships are real

## Browser

[ ] Browser process detection
[ ] Browser extension
[ ] Active tabs
[ ] Localhost handling
[ ] Multiple browser separation
[ ] No browser-history fabrication

## Network

[ ] LAN discovery still works
[ ] Device Scan still works
[ ] Open ports are real
[ ] Services are real
[ ] Versions are real
[ ] Live traffic remains functional
[ ] Traffic visibility is truthful
[ ] Per-device isolation works

## Vulnerability

[ ] NVD
[ ] CISA KEV
[ ] OSV
[ ] GHSA
[ ] Version range matching
[ ] Fixed version handling
[ ] No fabricated CVEs
[ ] OPEN != VULNERABLE

## AI

[ ] Current detection works
[ ] Forecasting is clearly marked prediction
[ ] LSTM status is truthful
[ ] Transformer status is truthful
[ ] GNN status is truthful
[ ] Confidence is real
[ ] Device-specific AI state

## Remediation

[ ] Existing Generate Fix remains working
[ ] Finding context reaches remediation
[ ] Fix is evidence-backed
[ ] Suggested fix is clearly distinguished from applied fix

## Telegram

[ ] Bot configured server-side
[ ] Real finding generates notification
[ ] Duplicate suppression works
[ ] State changes re-notify appropriately
[ ] API failure handled
[ ] No secret leakage

## Existing System

[ ] Dark UI unchanged
[ ] Device cards unchanged
[ ] Network/attack map unchanged
[ ] Device Scanner unchanged
[ ] CVE scanner unchanged
[ ] Live Traffic Tracker unchanged
[ ] Existing AI pipeline unchanged
[ ] Existing tests remain green
[ ] Production build succeeds

## Repository

[ ] GITHUB: UNTOUCHED

---

# 23. IMPLEMENTATION ORDER

Follow this order exactly:

```text
PHASE 01
Endpoint foundation
       ↓
PHASE 02
Endpoint telemetry
       ↓
PHASE 03
Vulnerability intelligence
       ↓
PHASE 04
Endpoint + Network + AI integration
       ↓
PHASE 05
Generate Fix + Telegram
       ↓
FINAL E2E
```

Do not skip directly to Phase 05.

Do not build a new system beside an already-working system.

Every phase must end with:

```text
IMPLEMENTED
+
UNIT TESTED
+
INTEGRATION TESTED
+
REGRESSION TESTED
```

and where possible:

```text
REAL E2E VERIFIED
```

---

# 24. REQUIRED PHASE REPORT FORMAT

At the end of EVERY phase, report:

## What existed before

## What changed

## Exact files modified

## Exact files created

## Architecture changes

## Dependencies

## Security/permission requirements

## Unit tests

## Integration tests

## Regression tests

## Real E2E test

## Known limitations

## What remains for the next phase

## Git status

And always explicitly state:

```text
GITHUB: UNTOUCHED
```

---

# 25. MASTER PRINCIPLE

Drishti must always prefer:

```text
REAL OBSERVATION
      ↓
STRUCTURED EVIDENCE
      ↓
DETERMINISTIC CORRELATION
      ↓
AI ANALYSIS
      ↓
EXPLAINED RESULT
      ↓
HUMAN-REVIEWED ACTION
```

Never:

```text
GUESS
 ↓
LABEL
 ↓
ALERT
```

The system should be impressive because it is **truthful, explainable,
device-specific, and evidence-backed**, not because it displays information
that it cannot actually observe.
