# Drishti Endpoint Agent — Phase 01: Foundation

## Architecture Overview
The Drishti Endpoint Agent provides authorized device-level visibility as a companion to Drishti's network discovery engine.

```text
Drishti Endpoint Agent
│
├── common/        # Cross-platform identity, config, lifecycle, and platform abstractions
├── windows/       # Windows genuine OS and hardware adapters
├── macos/         # macOS genuine OS and hardware adapters
├── transport/     # Zero-dependency HTTP transport client with retry & backoff
├── storage/       # Local credential and persistent identity storage (chmod 0600 on POSIX)
├── agent.py       # Main agent lifecycle orchestrator
└── cli.py         # Command-line entrypoint with SIGINT/SIGTERM handlers
```

## Running the Agent

### Start the Agent
```bash
python endpoint-agent/cli.py --server http://localhost:8000
```

### Pairing Flow
1. On startup, if unauthenticated, the agent generates a short-lived 8-character pairing code:
   ```text
   ===============================================================
                  DRISHTI ENDPOINT AGENT — PAIRING                
   ===============================================================
     Device Hostname : WORKSTATION-01
     Operating System: windows (Windows 11 (Build 26100))
     Device ID       : 550e8400-e29b-41d4-a716-446655440000
     Agent ID        : 123e4567-e89b-12d3-a456-426614174000
   ---------------------------------------------------------------
     PAIRING CODE    : AB7X-92KF
     EXPIRES AT      : 2026-09-20T16:45:00Z
   ---------------------------------------------------------------
     Enter this code in your Drishti SOC Dashboard:
     Dashboard / Live Watch -> Click 'Pair Endpoint Agent'
   ===============================================================
   ```
2. The dashboard operator enters `AB7X-92KF` in the "Pair Endpoint Agent" modal.
3. The backend validates the code, registers the agent to the operator's organization, and securely hands off an authenticated token.
4. The agent switches to `CONNECTED` and streams periodic heartbeats every 45s.
