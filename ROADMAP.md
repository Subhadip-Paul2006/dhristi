# 🗺️ Drishti: Product & Technical Roadmap

> **Current Version:** v1.0.0 (Championship Edition)  
> **Development Status:** Active Engineering Maintenance  
> **Contract:** Planned and future features are strictly distinguished from verified, production-ready capabilities.

---

## 1. Feature Status Classification

| Category | Definition | Current Status |
|---|---|---|
| **Implemented** | Fully coded, verified with unit/integration tests, and runnable in production. | ✅ Production Ready (v1.0.0) |
| **In Progress** | Active branch or pull request undergoing optimization and testing. | 🔄 Active Development |
| **Planned** | Approved architectural backlog scheduled for upcoming minor releases (v1.1 / v1.2). | 📋 Approved Architecture |
| **Future Work** | Long-term exploratory opportunities under conceptual evaluation (v2.0+). | 💡 Conceptual Exploration |

---

## 2. Implemented Features (v1.0.0 Championship Edition)

### Core Sensing & Ingestion
- [x] **Cross-Platform Endpoint Daemons:**
  - [x] Windows 10/11 x64 standalone PyInstaller binary (`Drishti-Agent.exe`).
  - [x] Apple macOS Launchd background daemon (`Drishti-Agent.pkg`).
  - [x] Android 14+ mobile agent (`Drishti-Agent.apk`) with Android Keystore encryption.
- [x] **Passive LAN Network Watcher:**
  - [x] ARP cache table inspection (`arp -a` / OS kernel).
  - [x] Reverse DNS (PTR) query resolver.
  - [x] Multicast DNS (mDNS / Bonjour) service discovery.
- [x] **Kernel Packet Ingestion Seam:**
  - [x] Multi-backend packet sniffing (Scapy 2.5, TShark, Zeek format reader).
  - [x] Low-level OS drivers (`AF_PACKET` on Linux, `/dev/bpf*` on macOS, `Npcap` on Windows).

### Analytical Core & Graph Intelligence
- [x] **Graph-Theoretic Attack Engine:**
  - [x] NetworkX directed graph representation ($G = (V, E)$).
  - [x] Yen's $K$-shortest paths algorithm computing top $K$ lateral breach routes.
  - [x] Graph Min-Cut algorithm identifying critical architectural chokepoints.
- [x] **Deterministic Dollar Risk Valuation:**
  - [x] Real-dollar exposure pricing based on CVSS severity, exploitability, and crown jewel valuation ($3.5M).
  - [x] Return on Mitigation (ROM) quantification.
- [x] **Vulnerability Intelligence:**
  - [x] Offline NVD and CISA Known Exploited Vulnerabilities (KEV) catalog integration.
  - [x] Exact version boundary matching: `[affected_start, fixed_version)`.
  - [x] 4-tier evidence hierarchy (`OBSERVED` $\to$ `CORRELATED` $\to$ `POTENTIAL` $\to$ `CONFIRMED`).

### AI Reasoning & Safe Remediation
- [x] **Generative Remediation Synthesis:**
  - [x] Anthropic Claude 3.5 Sonnet integration (`server/app/services/ai.py`).
  - [x] Generates Ansible playbooks, Cisco IOS ACLs, and PowerShell scripts.
- [x] **AST Safety Guardrail:**
  - [x] Python `ast.parse()` static analysis filter unconditionally blocking destructive calls (`rm`, `dd`, `mkfs`, `iptables -F`, etc.).

### User Presentation & Developer Experience
- [x] **Dark-Mode SOC Console (React 18 / Vite 5 / TailwindCSS):**
  - [x] Executive Posture Dashboard with real-time risk timeline.
  - [x] Interactive ReactFlow attack map canvas with animated path coloring.
  - [x] Unified Live Watch grid binding network sockets directly to process PIDs.
  - [x] Executive PDF and JSON compliance report generator.
- [x] **Standalone Vercel Demo Mode:**
  - [x] Offline evaluation preview with deterministic synthetic telemetry (`VITE_DEMO_MODE=true`).

---

## 3. In Progress (v1.0.1)

- [ ] **Performance Tuning on Large Topologies:**
  - [ ] Optimizing Yen's deviation loop for enterprise graphs exceeding 2,500 nodes.
  - [ ] In-memory Redis graph caching for distributed multi-sensor deployments.
- [ ] **Expanded Threat Feeds:**
  - [ ] Integrating MISP (Malware Information Sharing Platform) open threat intelligence feeds.

---

## 4. Planned Features (v1.1 – v1.2) «Planned»

- [ ] **Linux Server Daemon Package:**
  - [ ] Native `.deb` and `.rpm` systemd daemon packaging for Debian/Ubuntu and RHEL/Rocky Linux.
- [ ] **Cloud Asset Connectors:**
  - [ ] Read-only IAM ingestors for AWS VPC Flow Logs, Azure Virtual Network Taps, and Google Cloud VPC Flow.
- [ ] **Kubernetes Cluster Attack Surface Ingestion:**
  - [ ] Discovery of Pod-to-Pod Cilium / Calico network policies and RBAC privilege escalation graphs.
- [ ] **Automated Public Backend Deployment:**
  - [ ] Cloud-hosted backend environment with secure HSM secret management for paid AI credentials.

---

## 5. Future Work (v2.0+) «Future Work»

- [ ] **Hardware Network TAP Integration:**
  - [ ] Certified 10GbE / 40GbE optical network TAP appliances for continuous wire-speed monitoring.
- [ ] **Autonomous Air-Gapped LLM Deployments:**
  - [ ] Fully local, quantized open-weights LLMs (Llama 3 8B, DeepSeek-R1) running entirely on on-premise GPUs for classified military and intelligence enclaves.
- [ ] **Zero Trust Policy Synthesizer:**
  - [ ] Automated generation of microsegmentation policies for HashiCorp Consul, Istio Service Mesh, and Illumio.
