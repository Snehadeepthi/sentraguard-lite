"""SentraGuard Lite - FastAPI entrypoint.

Exactly two endpoints:
  POST /analyze  -> policy decision for a prompt + optional retrieved context
  GET  /policy   -> loaded policy/detector configuration
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.engine import Doc, analyze, summarize_for_log
from app.core.policy import get_policy
from app.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse, PolicyResponse

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger("sentraguard")


def log_event(event: str, **fields) -> None:
    """One JSON line per event. Only ids, counts, tags and timings - never text."""
    payload = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    logger.info(json.dumps(payload, sort_keys=True))


@asynccontextmanager
async def lifespan(_: FastAPI):
    policy = get_policy()  # load + compile once; a broken policy stops startup
    log_event("policy_loaded", version=policy.config.version, detectors=policy.config.detectors)
    yield


# Swagger/OpenAPI routes are off by default so the service exposes exactly the
# two specified endpoints. Set ENABLE_DOCS=true locally to get /docs.
_docs = os.getenv("ENABLE_DOCS", "false").lower() == "true"
app = FastAPI(
    title="SentraGuard Lite",
    version="1.0.0",
    description="Minimal GenAI guardrails gateway",
    lifespan=lifespan,
    docs_url="/docs" if _docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _docs else None,
)


def error_response(status: int, code: str, message: str, details: list | None = None) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "details": details or []}}
    return JSONResponse(status_code=status, content=body)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default 422 body echoes the offending input back, which could
    # contain PII. We return field + message only.
    details = [
        {"field": ".".join(str(p) for p in err["loc"] if p != "body") or "body", "message": err["msg"]}
        for err in exc.errors()
    ]
    log_event("request_rejected", status=422, error_count=len(details))
    return error_response(422, "validation_error", "Request payload failed validation.", details)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
    return error_response(exc.status_code, code, str(exc.detail))


@app.exception_handler(Exception)
async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    log_event("internal_error", error_type=type(exc).__name__)
    return error_response(500, "internal_error", "Unexpected server error.")


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    responses={400: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def analyze_endpoint(req: AnalyzeRequest):
    started = time.perf_counter()

    # Semantic check (valid JSON shape, but meaningless): duplicate doc ids
    # would make sanitized_context_docs ambiguous -> 400.
    ids = [d.id for d in req.context_docs]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        log_event("request_rejected", status=400, request_id=req.metadata.request_id)
        return error_response(
            400,
            "duplicate_doc_ids",
            "context_docs ids must be unique.",
            [{"field": "context_docs.id", "message": f"duplicate id(s): {', '.join(duplicates)}"}],
        )

    result = analyze(req.prompt, [Doc(d.id, d.text) for d in req.context_docs], get_policy())

    log_event(
        "analyze",
        request_id=req.metadata.request_id,
        app_id=req.metadata.app_id,
        prompt_chars=len(req.prompt),
        doc_count=len(req.context_docs),
        latency_ms=round((time.perf_counter() - started) * 1000, 2),
        **summarize_for_log(result),
    )
    return result


@app.get("/policy", response_model=PolicyResponse)
def policy_endpoint():
    return get_policy().public_view()
