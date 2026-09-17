# Drishti v0.1 — network-config vulnerability detection package | 12-Jul-2026
"""Detect real NAT / DMZ / DHCP misconfigurations from observed topology and/or
declared config, and feed the real ones into the existing risk engine.

  facts       — gather observed + declared network facts (no fabrication)
  detectors   — NAT / DMZ / DHCP checks; real vs unknown vs passed
  integration — map real findings to Vulnerability/AssetVulnerability records
  service     — orchestration, consent gate, recompute, persistence
"""
