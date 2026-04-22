"""
FastAPI integration for Sentinel.

Provides a Starlette/FastAPI middleware that screens request bodies and
an APIRouter that mirrors the Flask blueprint endpoints.

Usage::

    from fastapi import FastAPI
    from sentinel import Shield
    from sentinel.fastapi import ShieldMiddleware, create_shield_router

    shield = Shield()
    app = FastAPI()
    app.add_middleware(ShieldMiddleware, shield=shield)
    app.include_router(create_shield_router(shield), prefix="/shield")

Requires ``fastapi>=0.100.0`` (install with
``pip install sentinel[fastapi]``).
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from . import Shield, __version__

log = logging.getLogger(__name__)

_MAX_EXTRACT_DEPTH = 10


# ---- Middleware ----

class ShieldMiddleware(BaseHTTPMiddleware):
    """Screen JSON request bodies through Sentinel.

    Skips GET / DELETE / OPTIONS / HEAD and any paths in *excluded_paths*.
    On block, returns a 403 JSON response.

    Args:
        app: The ASGI application.
        shield: A ``Shield`` instance.
        mode: ``"block"`` to return 403, ``"monitor"`` to pass through.
        session_header: Header name that carries the session ID.
        excluded_paths: Set of path prefixes to skip.
    """

    def __init__(
        self,
        app: Any,
        shield: Shield,
        mode: str = "block",
        session_header: str = "X-Session-ID",
        excluded_paths: set[str] | None = None,
    ):
        super().__init__(app)
        self.shield = shield
        self.mode = mode
        self.session_header = session_header
        self.excluded_paths: set[str] = excluded_paths or set()

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        # Skip safe methods
        if request.method in ("GET", "DELETE", "OPTIONS", "HEAD"):
            response = await call_next(request)
            _add_security_headers(response)
            return response

        # Skip excluded paths
        for prefix in self.excluded_paths:
            if request.url.path.startswith(prefix):
                response = await call_next(request)
                _add_security_headers(response)
                return response

        # Read and screen body
        try:
            body = await request.body()
            if body:
                data = json.loads(body)
                strings = _extract_strings(data)
                session_id = _validated_session_id(
                    request.headers.get(self.session_header)
                )
                source_ip = request.client.host if request.client else "127.0.0.1"

                for text in strings:
                    result = self.shield.analyze(
                        text,
                        session_id=session_id,
                        source_ip=source_ip,
                    )
                    if result.blocked and self.mode == "block":
                        resp = JSONResponse(
                            status_code=403,
                            content={
                                "error": "Request blocked by Sentinel",
                                "verdict": result.verdict,
                                "detection_method": result.detection_method,
                            },
                        )
                        _add_security_headers(resp)
                        return resp
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.debug("Skipping non-JSON request body")

        response = await call_next(request)
        _add_security_headers(response)
        return response


def _add_security_headers(response: Any) -> None:
    """Append standard security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"


def _extract_strings(data: Any, depth: int = 0) -> list:
    """Recursively pull string values out of a JSON structure."""
    if depth > _MAX_EXTRACT_DEPTH:
        return []
    strings: list = []
    if isinstance(data, str):
        if data.strip():
            strings.append(data)
    elif isinstance(data, dict):
        for v in data.values():
            strings.extend(_extract_strings(v, depth + 1))
    elif isinstance(data, list):
        for item in data:
            strings.extend(_extract_strings(item, depth + 1))
    return strings


# ---- API Router ----

def _validated_session_id(raw: str | None) -> str:
    """Return *raw* if it is a valid UUID, otherwise generate a new one."""
    import uuid
    if raw:
        try:
            uuid.UUID(raw)
            return raw
        except ValueError:
            pass
    return str(uuid.uuid4())


class AnalyzeRequest(BaseModel):
    message: str
    session_id: str = ""


def create_shield_router(
    shield: Shield,
    require_api_key: bool = True,
    allow_unauthenticated: bool = False,
) -> APIRouter:
    """Create a FastAPI APIRouter that mirrors the Flask Shield blueprint.

    Endpoints:
        ``POST /analyze`` -- analyse a message
        ``GET  /health``  -- health check
        ``GET  /sessions`` -- list session summaries (auth required)

    Authentication:
        By default this router requires the ``SENTINEL_API_KEY`` env var to
        be set. If it is unset, ``create_shield_router`` raises
        ``RuntimeError`` at call time to prevent silently fail-open
        deployments (see CRIT F-01, 2026-04-22 audit). To intentionally run
        without authentication (local dev, trusted-network usage), pass
        ``allow_unauthenticated=True`` as an explicit opt-in.

    Args:
        shield: A ``Shield`` instance.
        require_api_key: If True, ``SENTINEL_API_KEY`` env var is enforced.
        allow_unauthenticated: Explicit opt-in to run without an API key.
            Must be True for the router to accept requests when
            ``SENTINEL_API_KEY`` is unset. Defaults to False (fail-closed).

    Raises:
        RuntimeError: When ``require_api_key`` is True, ``SENTINEL_API_KEY``
            is unset, and ``allow_unauthenticated`` is False.
    """
    api_key_configured = bool(os.getenv("SENTINEL_API_KEY", ""))
    if require_api_key and not api_key_configured and not allow_unauthenticated:
        raise RuntimeError(
            "SENTINEL_API_KEY is not set. Shield FastAPI router refuses to "
            "start fail-open. Set the SENTINEL_API_KEY environment "
            "variable, or pass allow_unauthenticated=True to "
            "create_shield_router() to explicitly opt in to unauthenticated "
            "access."
        )

    router = APIRouter()

    # ---- auth dependency ----

    async def verify_api_key(x_api_key: str | None = Header(None)):
        expected = os.getenv("SENTINEL_API_KEY", "")
        if not expected:
            if allow_unauthenticated:
                return  # Explicit opt-in: open access
            raise HTTPException(status_code=401, detail="Unauthorized")
        if not x_api_key or not hmac.compare_digest(
            x_api_key.encode(), expected.encode()
        ):
            raise HTTPException(status_code=401, detail="Unauthorized")

    # ---- rate-limit dependency ----

    async def check_rate_limit(request: Request):
        ip = request.client.host if request.client else "127.0.0.1"
        if not shield.check_rate_limit(ip):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # ---- endpoints ----

    auth_deps = [Depends(verify_api_key)] if require_api_key else []

    @router.post("/analyze", dependencies=auth_deps + [Depends(check_rate_limit)])
    async def analyze(body: AnalyzeRequest, request: Request):
        if not body.message or not body.message.strip():
            raise HTTPException(status_code=400, detail="Empty message")
        if len(body.message) > 10000:
            raise HTTPException(status_code=400, detail="Message too long (max 10000 chars)")

        source_ip = request.client.host if request.client else "127.0.0.1"
        session_id = _validated_session_id(body.session_id)
        result = shield.analyze(
            body.message,
            session_id=session_id,
            source_ip=source_ip,
        )
        return result.to_dict()

    @router.get("/health")
    async def health():
        return {
            "shield": "healthy",
            "version": __version__,
            "active_sessions": shield.session_manager.active_count,
        }

    @router.get("/sessions", dependencies=auth_deps)
    async def sessions():
        all_sessions = shield.session_manager.get_all()
        summary = [
            {
                "session_id": sid[:8] + "...",
                "interactions": len(s.get("interactions", [])),
                "threat_count": s.get("threat_count", 0),
                "escalated": s.get("escalated", False),
                "attack_patterns": s.get("attack_patterns", []),
            }
            for sid, s in all_sessions.items()
        ]
        return {"sessions": summary, "total": len(summary)}

    return router
