# Drishti v0.1 — deep-scan package | 12-Jul-2026
"""Consented, defensive deep scan of a device on the local network: real nmap
service/version detection → real CVE lookup → existing risk engine.

  scanner   — invoke nmap, structured available:false on failure
  parser    — nmap XML → services (open ports only)
  cve_lookup— match services to real CVEs (NVD default / Vulners), degrade cleanly
  integration — persist Asset/Service/Vulnerability + run recompute_org
  service   — orchestration, consent + RFC1918 gates, persistence
"""
