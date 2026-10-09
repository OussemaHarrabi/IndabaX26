"""Local HTTP boundary for deterministic AegisGraph decisions."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegisgraph import telemetry
from aegisgraph.access import ProblemError
from aegisgraph.api_admin import router as api_admin_router
from aegisgraph.api_v1 import router as api_v1_router
from aegisgraph.auth import AuthError
from aegisgraph.contracts import GuardDecision
from aegisgraph.engine import decide
from aegisgraph.sentinel import (
    MAX_RESPONSE_BYTES,
    SentinelRequest,
    SentinelResponse,
    wire_response,
)
from aegisgraph.settings import (
    LEGACY_ENV,
    Settings,
    load_settings,
    validate_settings,
)
from aegisgraph.store import open_store

_LOGGER = logging.getLogger(__name__)
_GENERIC_INVALID = {"detail": "Invalid SENTINEL request"}
_GENERIC_FAILURE = {"detail": "Request could not be safely processed"}
_GENERIC_TOO_LARGE = {"detail": "Request body exceeds the configured limit"}
_STATIC_DIRECTORY = Path(__file__).parent / "static"
_DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "connect-src 'none'; img-src 'self' data:; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

MAX_BODY_BYTES_ENV = "AEGISGRAPH_MAX_BODY_BYTES"
DEFAULT_MAX_BODY_BYTES = 1_048_576
"""Upper bound for a request body, enforced before the body is parsed (F5)."""

LOG_LEVEL_ENV = "AEGISGRAPH_LOG_LEVEL"
DEFAULT_LOG_LEVEL = logging.INFO
_DECISION_HANDLER_NAME = "aegisgraph-decision-stdout"


def log_level() -> int:
    """Return the configured service log level (default ``INFO``)."""

    raw = os.environ.get(LOG_LEVEL_ENV)
    if raw is None:
        return DEFAULT_LOG_LEVEL
    resolved = logging.getLevelNamesMapping().get(raw.strip().upper())
    return resolved if isinstance(resolved, int) else DEFAULT_LOG_LEVEL


class _DecisionStreamHandler(logging.Handler):
    """Write decision records to the current stdout.

    The stream is resolved at emit time rather than captured at construction, so
    output redirection (containers, pipes, test capture) is honoured.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            stream = sys.stdout
            stream.write(f"{self.format(record)}\n")
            stream.flush()
        except Exception:  # pragma: no cover - logging must never break a decision
            self.handleError(record)


def configure_logging() -> None:
    """Route ``aegisgraph`` records to stdout for the running service.

    The decision record is a structured JSON line, so the handler emits the
    message verbatim. Only the application boundary configures logging: importing
    a library module such as ``aegisgraph.engine`` never touches global logging
    state. The call is idempotent, so a reloaded application does not stack
    handlers. Records still propagate, so a host that configures the root logger
    keeps receiving them.
    """

    level = log_level()
    logger = logging.getLogger("aegisgraph")
    logger.setLevel(level)
    for handler in logger.handlers:
        if handler.get_name() == _DECISION_HANDLER_NAME:
            handler.setLevel(level)
            return
    handler = _DecisionStreamHandler()
    handler.set_name(_DECISION_HANDLER_NAME)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


app = FastAPI(
    title="AegisGraph SENTINEL v1 defense API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class BodySizeLimitMiddleware:
    """Reject oversized request bodies with 413 before any JSON parsing (F5).

    Both the declared ``Content-Length`` and the streamed body (chunked transfer
    encoding) are bounded: the declared size is rejected before the body is read,
    and a streamed body is buffered only until the bound is crossed. The request
    is then replayed downstream, so the bound is applied in front of parsing and
    memory never exceeds the configured size.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = max_body_bytes()
        headers = {key.lower(): value for key, value in scope["headers"]}
        declared = headers.get(b"content-length")
        if declared is not None and _declared_too_large(declared, limit):
            await _send_too_large(send)
            return

        chunks: list[bytes] = []
        received = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > limit:
                await _send_too_large(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


app.add_middleware(BodySizeLimitMiddleware)


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    """Serve the local, read-only investigation surface."""

    return FileResponse(_STATIC_DIRECTORY / "index.html", media_type="text/html")


app.mount("/assets", StaticFiles(directory=_STATIC_DIRECTORY), name="dashboard-assets")


@app.middleware("http")
async def no_store_and_sanitize_errors(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    try:
        response = await call_next(request)
    except Exception as error:
        _LOGGER.error("Unhandled HTTP boundary exception (%s)", type(error).__name__)
        response = JSONResponse(_GENERIC_FAILURE, status_code=500)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path == "/" or request.url.path.startswith("/assets/"):
        response.headers["Content-Security-Policy"] = _DASHBOARD_CSP
    return response


METRICS_ROUTE = "/metrics"
"""The Prometheus exposition route; excluded from its own request counter (M3)."""


@app.middleware("http")
async def record_request_metrics(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Count every handled request by route template, method and status (M3).

    The label is the matched route *template*, never the concrete path, so the
    series count stays bounded whatever identifiers a caller sends. An unmatched
    request is labelled ``unmatched`` and the ``/metrics`` scrape is excluded, so
    scraping does not feed its own series. Counting happens after the response is
    produced, and a telemetry failure cannot alter it.
    """

    response = await call_next(request)
    route = _route_template(request)
    if route != METRICS_ROUTE:
        telemetry.record_request(route, request.method, response.status_code)
    return response


def _route_template(request: Request) -> str:
    """Return the matched route template, or the bounded ``unmatched`` label."""

    template = getattr(request.scope.get("route"), "path", None)
    return template if isinstance(template, str) else telemetry.ROUTE_UNMATCHED


def max_body_bytes() -> int:
    """Return the configured request-body bound in bytes (default 1 MiB)."""

    raw = os.environ.get(MAX_BODY_BYTES_ENV)
    if raw is None:
        return DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES
    return value if value > 0 else DEFAULT_MAX_BODY_BYTES


def _declared_too_large(declared: bytes, limit: int) -> bool:
    try:
        return int(declared) > limit
    except ValueError:
        return True


async def _send_too_large(send: Send) -> None:
    body = json.dumps(_GENERIC_TOO_LARGE).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"pragma", b"no-cache"),
                (b"x-content-type-options", b"nosniff"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


app.include_router(api_v1_router)
app.include_router(api_admin_router)


@app.exception_handler(AuthError)
async def authentication_error_handler(_request: Request, error: AuthError) -> JSONResponse:
    """Return the authentication/authorization outcome without leaking the credential."""

    telemetry.record_auth_failure(error.code)
    headers = {"WWW-Authenticate": "Bearer"} if error.status_code == 401 else None
    return JSONResponse(
        {"detail": error.detail, "code": error.code},
        status_code=error.status_code,
        headers=headers,
    )


@app.exception_handler(ProblemError)
async def problem_error_handler(_request: Request, error: ProblemError) -> JSONResponse:
    """Return a bounded, machine-readable refusal for a protected surface."""

    return JSONResponse(
        {"detail": error.detail, "code": error.code}, status_code=error.status_code
    )


@app.exception_handler(RequestValidationError)
async def invalid_request_handler(_request: Request, _error: RequestValidationError) -> Response:
    return JSONResponse(_GENERIC_INVALID, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_request: Request, error: StarletteHTTPException) -> Response:
    # Keep routing status and method headers while dropping framework details.
    headers = {key: value for key, value in (error.headers or {}).items()}
    body = _GENERIC_INVALID if error.status_code in {400, 413, 415, 422} else _GENERIC_FAILURE
    return JSONResponse(body, status_code=error.status_code, headers=headers)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness only: the process answers, nothing about its dependencies (F1)."""

    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> JSONResponse:
    """Readiness, honest about the dependencies this revision needs (F1, F7).

    The body names the authentication mode, whether the receipt store is durable
    and whether that store currently answers. It carries no secret material: the
    service token digests, the JWKS document and the database URL are never echoed.
    """

    settings = load_settings()
    reachable = _store_reachable(settings)
    warnings: list[str] = []
    if settings.auth_mode.value != "required":
        warnings.append("AUTH_MODE_NONE")
    if settings.legacy_unauthenticated:
        warnings.append("LEGACY_UNAUTHENTICATED")
    if not settings.durable:
        warnings.append("RECEIPT_STORE_NOT_DURABLE")
    if not settings.production:
        warnings.append("NOT_PRODUCTION")
    dependencies: dict[str, object] = {
        "authentication": {
            "mode": settings.auth_mode.value,
            "jwt_configured": settings.jwt_enabled,
            "service_tokens_configured": len(settings.service_tokens),
            "legacy_unauthenticated": settings.legacy_unauthenticated,
        },
        "receipt_store": {"durable": settings.durable, "reachable": reachable},
        "environment": settings.environment.value,
    }
    # ``ready`` means "this process can serve traffic", which is what a probe needs.
    # ``insecure`` and ``warnings`` say whether it is serving *safely*; a process
    # with authentication off is ready but not production-safe (H3-05).
    ready = reachable
    insecure = bool(warnings)
    body = {
        "status": "ready" if ready else "degraded",
        "ready": ready,
        "insecure": insecure,
        "warnings": warnings,
        "dependencies": dependencies,
    }
    return JSONResponse(body, status_code=200 if ready else 503)


@app.get(METRICS_ROUTE, include_in_schema=False)
async def metrics() -> Response:
    """Serve the Prometheus exposition; an internal surface, opt-in in production (M3).

    The route answers only when metrics are enabled: on by default in development,
    and in production only with an explicit ``AEGISGRAPH_METRICS_ENABLED=true``.
    Production ingress is already restricted by the Kubernetes NetworkPolicy, so the
    surface is never reachable from outside the cluster.
    """

    if not telemetry.metrics_enabled():
        raise StarletteHTTPException(status_code=404, detail="Not Found")
    return Response(
        content=telemetry.render_metrics(), media_type=telemetry.metrics_content_type()
    )


def _store_reachable(settings: Settings) -> bool:
    try:
        return open_store(settings).ready()
    except Exception as error:  # pragma: no cover - a store that cannot even be built
        _LOGGER.error("Receipt store unavailable (%s)", type(error).__name__)
        return False


@app.post("/v1/decision", response_model=SentinelResponse)
async def decision_endpoint(request: SentinelRequest) -> Response:
    """Return one bounded policy decision; candidate actions are never executed.

    This is the frozen SENTINEL wire. It is available only in the labelled
    development mode, is refused in production at startup, and is deliberately not
    receipt-bearing: its measured behaviour must not change (D5).
    """

    settings = load_settings()
    if not settings.legacy_unauthenticated:
        _LOGGER.warning("Legacy unauthenticated surface refused (%s is not enabled)", LEGACY_ENV)
        raise StarletteHTTPException(status_code=404, detail="Not Found")
    try:
        result = decide(request, ablation=settings.ablation)
        response = _to_wire_response(result)
        encoded = response.model_dump_json().encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise ValueError("decision response exceeded protocol response bound")
        return Response(content=encoded, media_type="application/json", status_code=200)
    except Exception as error:
        _LOGGER.error("Decision response validation failed (%s)", type(error).__name__)
        # A valid request reaching policy must never become an allow on an error.
        fallback = SentinelResponse(
            decision="block",
            risk_score=1.0,
            confidence=1.0,
            reason_codes=("INTERNAL_EVALUATION_FAILED",),
            explanation="The request could not be safely evaluated.",
            metadata={},
        )
        return Response(
            content=fallback.model_dump_json(), media_type="application/json", status_code=200
        )


def _to_wire_response(decision: GuardDecision) -> SentinelResponse:
    """Translate canonical enums into the strict public response contract."""

    return wire_response(decision)


def configure_configuration() -> Settings:
    """Validate the configuration at startup and refuse an unsafe process (D7).

    A production process configured with ``AEGISGRAPH_AUTH_MODE=none``, with the
    legacy unauthenticated surface enabled, with no durable receipt store, or with
    a required secret missing raises here — at import, before the server binds —
    so the deployment fails closed with a non-zero exit instead of serving.
    """

    settings = load_settings()
    validate_settings(settings)
    return settings


configure_configuration()
configure_logging()
