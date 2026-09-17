# Drishti Edge Agent

Single-file, stdlib-only Python agent. It collects an asset/service/vulnerability
snapshot (in the demo, from a consented fixture file), **filters it on the host**
so only compact metadata leaves the machine, and POSTs it to `/api/ingest`.

## Run (demo fixture)

```bash
python3 drishti_agent.py --once \
  --fixture ../server/app/seed/fixtures/db-prod-01.json \
  --server http://localhost:8000 \
  --token agent-demo-token
```

## Run (interval mode)

```bash
python3 drishti_agent.py --interval 300 --severity-floor medium \
  --server http://localhost:8000 --token agent-demo-token
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--server` | `http://localhost:8000` | Drishti server URL |
| `--token` | (required) | per-agent bearer token |
| `--fixture` | — | consented scan fixture to replay (demo mode) |
| `--once` | — | post one snapshot and exit |
| `--interval` | 300 | seconds between posts |
| `--severity-floor` | `low` | drop vulns below this severity (edge filtering) |
| `--batch-size` | 100 | cap list sizes per payload |

## Behavior

- Exponential backoff on 5xx/network errors (1s, 2s, 4s), then gives up that cycle.
- 4xx responses fail fast (bad token / payload — retrying won't help).
- Idempotent server-side: the same host identity updates the same asset.
- Payloads target < 50 KB — bandwidth scales with **assets**, not traffic.

## Scope guardrail

The agent inventories the host it runs on or replays fixtures. It performs **no
scanning of third-party systems** and sends **metadata only** — never raw packets.
