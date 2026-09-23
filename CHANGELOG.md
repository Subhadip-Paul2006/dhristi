# 📝 Drishti Changelog

All notable changes to the **Drishti** platform are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-09-23

### Added
- **Visual Intelligence Assets:**
  - 8 original responsive, animated SVGs in `assets/svg/` covering Network Topology, Traffic Flow, Network Discovery, Low-Level Packet Flow, 27-Feature Canonical Analysis, Attack Paths, AI Reasoning, and Full-System Architecture.
  - Full `@media (prefers-reduced-motion: reduce)` accessibility fallbacks on all animated SVG assets.
  - Organized genuine UI screenshot gallery in `assets/screenshots/` (9 captured views).
- **Standalone Vercel Demo Mode:**
  - Added `VITE_DEMO_MODE=true` environment flag enabling isolated frontend deployment on Vercel without requiring a live backend.
  - Deterministic synthetic telemetry mocks for Dashboard, Attack Map, Live Watch, Findings, Assets, and Reports.
- **Documentation Architecture:**
  - Comprehensive rewrite of `README.md` into an evaluator-friendly master technical landing page.
  - Complete REST and WebSocket API specification in `API.md` (16 routers).
  - Scientific whitepaper in `RESEARCH.md` documenting graph math, Yen's algorithm, and 27-feature flow profiling.
  - Evaluator and user operational guide in `USAGE.md` with screenshot walkthroughs.
  - Detailed sub-architecture guides in `docs/architecture/`, `docs/research/`, and `docs/guides/`.

### Changed
- Normalized root filenames to lowercase Markdown extensions (`PRD.md`, `TRD.md`, `SECURITY.md`).
- Upgraded `SETUP.md` with auto-detecting operating system setup procedures for Windows, macOS, and Linux.

---

## [1.0.0] - 2026-09-20 (IIT Hackathon Championship Edition)

### Added
- **Core Sensing & Ingestion:**
  - Cross-platform endpoint agents for Windows (`Drishti-Agent.exe`), macOS (`Drishti-Agent.pkg`), and Android (`Drishti-Agent.apk`).
  - Passive LAN discovery via ARP table inspection, reverse DNS queries, and mDNS announcements.
  - Kernel packet capture adapter supporting Scapy 2.5, TShark, and Zeek packet formats via `AF_PACKET`, `/dev/bpf*`, and `Npcap`.
- **Graph & Analytical Engine:**
  - NetworkX directed attack graph representation with logarithmic exploitability edge weights.
  - Yen's $K$-shortest paths algorithm calculating top candidate breach routes.
  - Graph Min-Cut algorithm identifying critical architectural chokepoints.
  - Deterministic dollar risk pricing model calculating real financial liability ($ USD) based on crown jewel valuation ($3.5M).
  - Offline vulnerability correlation matching software products against NVD and CISA KEV catalogs.
- **AI Remediation & Guardrails:**
  - Anthropic Claude 3.5 Sonnet integration synthesizing Ansible playbooks, Cisco IOS ACLs, and PowerShell scripts.
  - Abstract Syntax Tree (AST) guardrail filter statically inspecting generated scripts and blocking destructive commands (`rm`, `dd`, `mkfs`, `iptables -F`, etc.).
- **User Presentation:**
  - Dark-mode React 18 / TypeScript / Vite 5 SOC console with ReactFlow attack canvas and Live Watch socket-to-PID grid.
  - Deduplicated Telegram alerting bot.
  - Executive PDF report generation.
- **Automated Verification:**
  - 408 backend tests passing with pytest.
  - 82 frontend unit and component tests passing with Vitest.
