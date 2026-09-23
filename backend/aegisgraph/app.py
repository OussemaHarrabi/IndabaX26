"""Local HTTP boundary for deterministic AegisGraph decisions."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint

from aegisgraph.contracts import GuardDecision, Verdict
from aegisgraph.engine import decide
from aegisgraph.sentinel import SentinelRequest, SentinelResponse

_LOGGER = logging.getLogger(__name__)
_MAX_RESPONSE_BYTES = 64_000
_GENERIC_INVALID = {"detail": "Invalid SENTINEL request"}
_GENERIC_FAILURE = {"detail": "Request could not be safely processed"}

app = FastAPI(
    title="AegisGraph SENTINEL v1 defense API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


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
    return response


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
    return {"status": "ok"}


@app.post("/v1/decision", response_model=SentinelResponse)
async def decision_endpoint(request: SentinelRequest) -> Response:
    """Return one bounded policy decision; candidate actions are never executed."""

    try:
        result = decide(request)
        response = _to_wire_response(result)
        encoded = response.model_dump_json().encode("utf-8")
        if len(encoded) > _MAX_RESPONSE_BYTES:
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

    payload = decision.model_dump(mode="json")
    payload["decision"] = Verdict(decision.verdict).value
    payload.pop("verdict", None)
    return SentinelResponse.model_validate(payload)
