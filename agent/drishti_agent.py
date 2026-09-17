#!/usr/bin/env python3
# Drishti v0.1 — lightweight edge collection agent | 11-Jul-2026
"""Drishti Edge Agent — single-file, stdlib-only.

Collects (or reads from a fixture) an asset + service + vulnerability snapshot,
pre-filters it on the host (the Edge-Filtering pillar), and POSTs compact JSON
metadata to the Drishti server. Raw traffic never leaves the host.

Defensive scope: this agent inventories the host it runs on (or replays a
consented fixture). It performs no network scanning of third-party systems.

Usage:
  python3 drishti_agent.py --once --fixture ../server/app/seed/fixtures/db-prod-01.json \
      --server http://localhost:8000 --token agent-demo-token
  python3 drishti_agent.py --interval 300 --severity-floor medium ...
"""
import argparse
import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MAX_PAYLOAD_BYTES = 50_000  # keep payloads small; bandwidth scales with assets
BACKOFF_SCHEDULE = [1, 2, 4]  # seconds; capped exponential backoff


def log(msg: str) -> None:
    print(f"[drishti-agent] {msg}", flush=True)


def collect_local_snapshot(agent_id: str, org_slug: str) -> dict:
    """Minimal self-inventory when no fixture is given: identity only.

    Real service/vuln detection would integrate a local scanner here; the demo
    uses fixtures so no third-party system is ever touched.
    """
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except OSError:
        ip = "127.0.0.1"
    return {
        "agent_id": agent_id,
        "org_slug": org_slug,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "host": {
            "hostname": hostname,
            "ip": ip,
            "os": f"{platform.system()} {platform.release()}",
            "asset_type": "workstation",
        },
        "services": [],
        "vulnerabilities": [],
        "connectivity": [],
    }


def apply_filters(payload: dict, severity_floor: str, batch_size: int) -> dict:
    """Edge filtering (ARCHITECTURE.md §3.5): keep signal, drop noise.

    - keep only schema fields (whitelist)
    - drop vulnerabilities below the severity floor
    - cap list sizes to the batch size
    """
    floor = SEVERITY_RANK.get(severity_floor, 0)

    host = payload.get("host", {})
    filtered = {
        "agent_id": payload["agent_id"],
        "org_slug": payload["org_slug"],
        "collected_at": payload.get("collected_at")
        or datetime.now(timezone.utc).isoformat(),
        "host": {
            k: host[k]
            for k in ("hostname", "ip", "os", "asset_type", "zone_hint", "criticality_hint")
            if k in host and host[k] is not None
        },
        "services": [
            {k: s[k] for k in ("port", "protocol", "name", "version") if k in s}
            for s in payload.get("services", [])[:batch_size]
        ],
        "vulnerabilities": [
            {
                k: v[k]
                for k in ("cve_id", "title", "cvss", "severity", "exploitability", "port", "summary")
                if k in v
            }
            for v in payload.get("vulnerabilities", [])
            if SEVERITY_RANK.get(v.get("severity", "low"), 0) >= floor
        ][:batch_size],
        "connectivity": [
            {k: c[k] for k in ("to_ip", "via", "note") if k in c}
            for c in payload.get("connectivity", [])[:batch_size]
        ],
    }
    return filtered


def post_payload(server: str, token: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    if len(body) > MAX_PAYLOAD_BYTES:
        log(f"warning: payload {len(body)}B exceeds {MAX_PAYLOAD_BYTES}B target after filtering")
    req = urllib.request.Request(
        f"{server.rstrip('/')}/api/ingest",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    last_error: Exception | None = None
    for attempt, delay in enumerate([0, *BACKOFF_SCHEDULE]):
        if delay:
            log(f"retrying in {delay}s (attempt {attempt + 1})")
            time.sleep(delay)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code < 500:
                # 4xx = our fault; retrying won't help. Fail fast and loud.
                detail = e.read().decode()[:400]
                raise SystemExit(f"[drishti-agent] rejected ({e.code}): {detail}")
            last_error = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_error = e
    raise SystemExit(f"[drishti-agent] giving up after retries: {last_error}")


def run_once(args: argparse.Namespace) -> None:
    if args.fixture:
        with open(args.fixture) as f:
            raw = json.load(f)
        raw.setdefault("agent_id", args.agent_id)
        raw.setdefault("org_slug", args.org_slug)
    else:
        raw = collect_local_snapshot(args.agent_id, args.org_slug)

    payload = apply_filters(raw, args.severity_floor, args.batch_size)
    size = len(json.dumps(payload).encode())
    log(
        f"posting {payload['host'].get('hostname', '?')} "
        f"({len(payload['services'])} services, {len(payload['vulnerabilities'])} vulns, {size}B)"
    )
    result = post_payload(args.server, args.token, payload)
    if not isinstance(result, dict):
        raise SystemExit(
            f"[drishti-agent] unexpected response shape from server: {type(result).__name__}"
        )
    log(f"accepted: asset={result.get('asset_id')} ingested={result.get('ingested')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Drishti edge agent")
    # http://localhost:8000 is a dev convenience default; point --server (or the
    # deployment config) at the real ingest endpoint in production.
    parser.add_argument("--server", default="http://localhost:8000")
    parser.add_argument(
        "--token",
        required=False,
        default=None,
        # The bearer token is sourced from the DRISHTI_AGENT_TOKEN env var when
        # --token is omitted (resolved below). There is intentionally NO
        # hardcoded token fallback: production MUST provide a real agent token
        # via --token or DRISHTI_AGENT_TOKEN, or the agent refuses to start.
        help="agent bearer token (or set DRISHTI_AGENT_TOKEN)",
    )
    parser.add_argument("--agent-id", default="agent-demo")
    parser.add_argument("--org-slug", default="acme-retail")
    parser.add_argument("--fixture", help="path to a consented scan fixture (demo mode)")
    parser.add_argument("--once", action="store_true", help="post one snapshot and exit")
    parser.add_argument("--interval", type=int, default=300, help="seconds between posts")
    parser.add_argument(
        "--severity-floor",
        choices=["low", "medium", "high"],
        default="low",
        help="drop vulnerabilities below this severity",
    )
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()

    args.token = args.token or os.environ.get("DRISHTI_AGENT_TOKEN")
    if not args.token:
        parser.error("--token or DRISHTI_AGENT_TOKEN environment variable is required")

    if args.once:
        run_once(args)
        return
    log(f"running every {args.interval}s (Ctrl-C to stop)")
    while True:
        try:
            run_once(args)
        except SystemExit as e:
            log(str(e))  # never crash the host loop on a failed post
        except Exception as e:
            log(f"unexpected error: {e}")  # never crash the host loop on a failed post
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
