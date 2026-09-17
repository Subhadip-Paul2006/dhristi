# Drishti v0.1 — FastAPI application bootstrap | 11-Jul-2026
"""FastAPI app assembly: lifespan bootstrap, middleware, error handlers, routers."""
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.config import get_settings
from app.core.errors import envelope, register_error_handlers

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("drishti")


def _bootstrap() -> None:
    """Ensure tables exist and seed the demo network on a fresh DB so a bare
    `uvicorn app.main:app` (or first Docker boot) is alive on first load
    (demo-first mindset). Idempotent: only seeds when the DB has no org."""
    import app.models  # noqa: F401  (register mappers)
    from app.db import Base, SessionLocal, engine
    from app.db_init import reconcile_columns
    from app.models import Organization

    Base.metadata.create_all(engine)
    # create_all won't add columns to a pre-existing table; reconcile additive
    # columns so a stale dev DB / Docker volume doesn't 500 on new fields.
    reconcile_columns(engine)
    # legacy device rows predate the subnet column — backfill /24, marked inferred
    db = SessionLocal()
    try:
        from app.services.live import backfill_device_subnets

        n = backfill_device_subnets(db)
        if n:
            logger.info(json.dumps({"event": "subnet_backfill", "rows": n}))
    except Exception:
        logger.exception("subnet backfill failed (continuing)")
    finally:
        db.close()
    settings = get_settings()
    if not settings.auto_seed:
        return
    db = SessionLocal()
    try:
        if db.scalar(select(Organization)) is None:
            # Default: identity only — the attack map / live watch start empty and
            # fill only with the real devices the agent discovers, so no fabricated
            # device ever ships. DEMO_SEED=1 boots the Acme sample network instead.
            if settings.demo_seed:
                from app.seed.acme import seed_acme
                from app.services.recompute import recompute_org

                org = seed_acme(db)
                recompute_org(db, org.id)
                db.commit()
                logger.info(json.dumps({"event": "bootstrap_seeded", "org": org.slug, "mode": "demo"}))
            else:
                from app.seed.acme import seed_identity

                org = seed_identity(db)
                logger.info(json.dumps({"event": "bootstrap_seeded", "org": org.slug, "mode": "live"}))
    except Exception:
        logger.exception("bootstrap seed failed (continuing)")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        _bootstrap()
    except Exception:
        logger.exception("bootstrap failed")
    # start the autonomous deep-scan scheduler (skipped under pytest so tests
    # never trigger a real nmap subprocess). It only acts on orgs that have
    # explicitly enabled autoscan, so it's a no-op until a user turns it on.
    import sys

    if "pytest" not in sys.modules:
        try:
            from app.services import autoscan

            autoscan.start()
        except Exception:
            logger.exception("autoscan scheduler failed to start")
            
        # Telegram alert dispatcher — every 30s scan for new high/critical findings
        # and active network threats, send Telegram notifications (disabled when
        # TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not configured).
        try:
            from app.services.telegram_alerts import start as start_telegram_alerts

            start_telegram_alerts()
        except Exception:
            logger.exception("telegram alert service failed to start")

        # Auto-start the local watch agent in dev environments only (skip in prod).
        import subprocess
        import os
        agent_process = None
        try:
            agent_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../agent/drishti_watch.py"))
            if os.path.exists(agent_script):
                agent_process = subprocess.Popen([
                    sys.executable, agent_script, 
                    "--mode", "devices", 
                    "--consent-subnet",
                    "--discover-wifi",
                    "--server", "http://127.0.0.1:8000", 
                    "--token", "agent-demo-token"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("Auto-started drishti_watch.py background agent (mode=devices, wifi=true)")
        except Exception:
            logger.exception("failed to auto-start drishti_watch.py")
            
    yield
    
    if "pytest" not in sys.modules and agent_process:
        try:
            agent_process.terminate()
            agent_process.wait(timeout=2)
            logger.info("Stopped background agent")
        except Exception:
            pass


class MaxBodySizeMiddleware:
    """Raw ASGI middleware enforcing max_bytes on the incoming request body.

    Reads the request stream incrementally and rejects with 413 as soon as
    the configured limit is exceeded, before the body is ever fully buffered
    into memory — this is what protects /api/ingest from a pre-auth DoS via a
    huge or unbounded (no Content-Length / chunked transfer-encoding) body.
    core.deps.reject_oversized only covers the honest-Content-Length fast
    path and runs after FastAPI has already buffered the body, so it stays as
    defense-in-depth, not the primary control.

    Buffers accepted chunks itself and replays them to the wrapped app rather
    than raising an exception from within receive(): FastAPI's own
    body-parsing (fastapi.routing) re-catches any exception that isn't a bare
    HTTPException and converts it to a generic 400, and structured_log's
    BaseHTTPMiddleware further re-wraps exceptions raised through its
    receive() via an anyio task group — either of which would swallow the
    real 413 before it reaches the client.
    """

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        buffered = []
        seen = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                buffered.append(message)
                break
            seen += len(message.get("body", b""))
            if seen > self.max_bytes:
                response = JSONResponse(
                    status_code=413,
                    content=envelope("validation_error", "Payload too large"),
                )
                await response(scope, receive, send)
                return
            buffered.append(message)
            if not message.get("more_body", False):
                break

        async def replay_receive():
            if buffered:
                return buffered.pop(0)
            return await receive()

        await self.app(scope, replay_receive, send)


app = FastAPI(title="Drishti", version="0.1.0", lifespan=lifespan)

settings = get_settings()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    # The Chrome extension (Drishti Web Guard) calls /api/auth/* and
    # /api/url-analyzer/analyze from a chrome-extension:// origin whose id is only
    # known once it's loaded, so match the scheme by regex rather than listing an
    # id. Extension requests carry a Bearer token, not cookies.
    allow_origin_regex=r"chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_error_handlers(app)


@app.middleware("http")
async def structured_log(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    request.state.request_id = request_id
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        logger.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": 500,
                    "latency_ms": latency_ms,
                }
            )
        )
        raise
    latency_ms = round((time.perf_counter() - start) * 1000, 1)
    logger.info(
        json.dumps(
            {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "latency_ms": latency_ms,
            }
        )
    )
    return response


# Registered last so it becomes the outermost ASGI layer (Starlette wraps
# most-recently-added middleware first), catching oversized bodies before
# structured_log/CORS/routing ever see them.
app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.ingest_max_bytes)


def _register_routers() -> None:
    from app.api import (
        ai, assets, auth, dashboard, findings, graph, health, ingest, live, netconfig,
        org, paths, report, urltrust,
    )

    app.include_router(health.router)
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(org.router, prefix="/api", tags=["org"])
    app.include_router(ingest.router, prefix="/api", tags=["ingest"])
    app.include_router(assets.router, prefix="/api", tags=["assets"])
    app.include_router(findings.router, prefix="/api", tags=["findings"])
    app.include_router(graph.router, prefix="/api", tags=["graph"])
    app.include_router(paths.router, prefix="/api", tags=["paths"])
    app.include_router(ai.router, prefix="/api/ai", tags=["ai"])
    app.include_router(dashboard.router, prefix="/api", tags=["dashboard"])
    app.include_router(report.router, prefix="/api", tags=["report"])
    app.include_router(live.router, prefix="/api", tags=["live"])
    app.include_router(netconfig.router, prefix="/api", tags=["netconfig"])
    app.include_router(urltrust.router, prefix="/api", tags=["url-analyzer"])


_register_routers()
