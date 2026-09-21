# Drishti v0.1 — Endpoint Agent CLI Entrypoint | Phase 01
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

# Ensure endpoint-agent root is on sys.path
AGENT_ROOT = Path(__file__).resolve().parent
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from agent import DrishtiEndpointAgent
from common.config import AgentConfig


def main() -> None:
    parser = argparse.ArgumentParser(description="Drishti Endpoint Agent (Phase 01)")
    parser.add_argument(
        "--server",
        default=os.environ.get("DRISHTI_SERVER_URL", "http://localhost:8000"),
        help="Drishti Backend Server URL (default: http://localhost:8000 or DRISHTI_SERVER_URL env var)",
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("DRISHTI_STATE_DIR"),
        help="Custom directory for identity and credentials storage (default: ~/.drishti/agent or DRISHTI_STATE_DIR env var)",
    )
    parser.add_argument(
        "--heartbeat-interval",
        type=float,
        default=45.0,
        help="Heartbeat reporting interval in seconds (default: 45s)",
    )
    parser.add_argument(
        "--force-pair",
        action="store_true",
        default=False,
        help="Clear saved credentials and force a fresh pairing flow on every start. "
             "Use this whenever the dashboard reports 'Invalid pairing code'.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable detailed debug logging",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    config = AgentConfig(
        server_url=args.server.rstrip("/"),
        state_dir=args.state_dir,
        heartbeat_interval_seconds=args.heartbeat_interval,
    )

    agent = DrishtiEndpointAgent(config=config, force_pair=args.force_pair)

    def handle_signal(sig, frame):
        print("\n[Drishti Agent] Caught termination signal. Shutting down cleanly...")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    agent.start(block=True)


if __name__ == "__main__":
    main()
