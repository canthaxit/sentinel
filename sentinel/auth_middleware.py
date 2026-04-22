"""
Sentinel - Authentication/Authorization Middleware
Flask middleware for API key and Basic auth with tenant/user resolution.
"""

from __future__ import annotations

import base64
import functools
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .rbac import Permission, RBACManager
    from .tenant import TenantManager

log = logging.getLogger(__name__)


def require_auth(
    tenant_manager: TenantManager | None = None,
    rbac_manager: RBACManager | None = None,
    permission: Permission | None = None,
):
    """Flask decorator that enforces authentication and authorization.

    Supports two auth methods:

    1. **API key** -- ``X-API-Key`` header or ``Authorization: Bearer <key>``.
       Resolves a tenant via *tenant_manager*.
    2. **Basic auth** -- ``Authorization: Basic <base64>``.
       Authenticates a user via *rbac_manager*.

    On success, attaches ``g.tenant`` and/or ``g.user`` to the Flask
    request context.  On failure, returns 401 or 403.

    Usage::

        @app.route("/analyze", methods=["POST"])
        @require_auth(tenant_manager=tm, permission=Permission.ANALYZE)
        def analyze():
            tenant = g.tenant  # may be None
            user = g.user      # may be None
            ...
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                from flask import g, jsonify, request
            except ImportError:
                raise RuntimeError("Flask is required for auth middleware")

            g.tenant = None
            g.user = None

            auth_header = request.headers.get("Authorization", "")
            api_key_header = request.headers.get("X-API-Key", "")

            authenticated = False

            # Method 1: X-API-Key header
            if api_key_header and tenant_manager is not None:
                tenant = tenant_manager.resolve_by_api_key(api_key_header)
                if tenant is not None:
                    g.tenant = tenant
                    authenticated = True

            # Method 2: Authorization: Bearer <key>
            elif auth_header.startswith("Bearer ") and tenant_manager is not None:
                key = auth_header[7:]
                tenant = tenant_manager.resolve_by_api_key(key)
                if tenant is not None:
                    g.tenant = tenant
                    authenticated = True

            # Method 3: Authorization: Basic <base64>
            elif auth_header.startswith("Basic ") and rbac_manager is not None:
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                    username, password = decoded.split(":", 1)
                    user = rbac_manager.authenticate(username, password)
                    if user is not None:
                        g.user = user
                        authenticated = True
                        # Resolve tenant for tenant-scoped users
                        if user.tenant_id and tenant_manager is not None:
                            g.tenant = tenant_manager.get_tenant(user.tenant_id)
                except (ValueError, TypeError, UnicodeDecodeError):
                    pass  # Malformed Basic auth header - fall through to 401

            # No managers configured = deny by default (secure default)
            if tenant_manager is None and rbac_manager is None:
                log.warning("require_auth called with no managers configured -- denying request")
                return jsonify({"error": "Authentication not configured"}), 401

            if not authenticated:
                return jsonify({"error": "Unauthorized"}), 401

            # Authorization check
            if permission is not None:
                if g.user is not None and rbac_manager is not None:
                    if not rbac_manager.authorize(g.user, permission):
                        return jsonify({"error": "Forbidden"}), 403
                elif g.tenant is not None:
                    # API key auth: only allow basic operations, not admin
                    from .rbac import Permission as _Perm
                    _API_KEY_ALLOWED = (
                        _Perm.ANALYZE,
                        _Perm.VIEW_DASHBOARD,
                        _Perm.VIEW_SESSIONS,
                        _Perm.VIEW_METRICS,
                    )
                    if permission not in _API_KEY_ALLOWED:
                        return jsonify({"error": "Forbidden -- API key insufficient for this operation"}), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator
