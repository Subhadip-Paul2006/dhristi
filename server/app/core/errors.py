# Drishti v0.1 — unified error envelope | 11-Jul-2026
"""One error envelope everywhere (ERROR_HANDLING.md §1).

{ "error": { "code": "...", "message": "...", "detail": ... } }
"""
import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("drishti")

# Closed set of error codes — the frontend switches on these.
CODES = {
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    413: "validation_error",
    422: "validation_error",
    429: "rate_limited",
    502: "ai_unavailable",
    500: "internal_error",
}


class DomainError(Exception):
    """Service-layer error; HTTP-agnostic (routers/adapters map to status)."""

    status = 500
    code = "internal_error"

    def __init__(self, message: str, detail: object | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


class NotFoundError(DomainError):
    status = 404
    code = "not_found"


class ConflictError(DomainError):
    status = 409
    code = "conflict"


class UnauthorizedError(DomainError):
    status = 401
    code = "unauthorized"


class ForbiddenError(DomainError):
    status = 403
    code = "forbidden"


class RateLimitedError(DomainError):
    status = 429
    code = "rate_limited"


class AIUnavailableError(DomainError):
    status = 502
    code = "ai_unavailable"


def envelope(code: str, message: str, detail: object | None = None) -> dict:
    return {"error": {"code": code, "message": message, "detail": detail}}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError):
        return JSONResponse(
            status_code=exc.status,
            content=envelope(exc.code, exc.message, exc.detail),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        code = CODES.get(exc.status_code, "internal_error")
        detail = None
        message = str(exc.detail)
        if isinstance(exc.detail, dict):
            message = exc.detail.get("message", "Error")
            code = exc.detail.get("code", code)
            detail = exc.detail.get("detail")
        return JSONResponse(status_code=exc.status_code, content=envelope(code, message, detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        fields = [
            {"loc": ".".join(str(p) for p in e.get("loc", [])), "msg": e.get("msg", "")}
            for e in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=envelope("validation_error", "Request validation failed", fields),
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())[:8]
        logger.exception("unhandled error request_id=%s path=%s", request_id, request.url.path)
        return JSONResponse(
            status_code=500,
            content=envelope("internal_error", "Something went wrong", {"request_id": request_id}),
        )
