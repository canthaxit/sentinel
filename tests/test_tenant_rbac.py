"""
Tests for multi-tenancy, RBAC, and auth middleware.
Run: python -m pytest tests/test_tenant_rbac.py -v
"""

import base64
import threading
import time

import pytest

from sentinel.tenant import Tenant, TenantManager, _hash_key
from sentinel.rbac import (
    Permission,
    RBACManager,
    ROLE_PERMISSIONS,
    User,
    _hash_password,
    _verify_password,
)


# ============================================================
# TenantManager Tests
# ============================================================


class TestTenantManager:

    def test_create_tenant(self):
        mgr = TenantManager()
        tenant, key = mgr.create_tenant("t1", "Acme Corp")
        assert tenant.tenant_id == "t1"
        assert tenant.name == "Acme Corp"
        assert tenant.enabled is True
        assert len(key) > 20  # secrets.token_urlsafe(32) produces ~43 chars

    def test_create_duplicate_raises(self):
        mgr = TenantManager()
        mgr.create_tenant("t1", "Acme")
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_tenant("t1", "Acme 2")

    def test_get_tenant(self):
        mgr = TenantManager()
        mgr.create_tenant("t1", "Acme")
        assert mgr.get_tenant("t1").name == "Acme"
        assert mgr.get_tenant("missing") is None

    def test_list_tenants(self):
        mgr = TenantManager()
        mgr.create_tenant("a", "Alpha")
        mgr.create_tenant("b", "Beta")
        names = {t.name for t in mgr.list_tenants()}
        assert names == {"Alpha", "Beta"}

    def test_update_tenant(self):
        mgr = TenantManager()
        mgr.create_tenant("t1", "Acme")
        mgr.update_tenant("t1", name="Acme Inc", tags=["prod"])
        t = mgr.get_tenant("t1")
        assert t.name == "Acme Inc"
        assert t.tags == ["prod"]

    def test_update_tenant_config_overrides_merge(self):
        mgr = TenantManager()
        mgr.create_tenant("t1", "Acme", config_overrides={"ml_high": 0.9})
        mgr.update_tenant("t1", config_overrides={"ml_low": 0.2})
        t = mgr.get_tenant("t1")
        assert t.config_overrides == {"ml_high": 0.9, "ml_low": 0.2}

    def test_update_nonexistent_raises(self):
        mgr = TenantManager()
        with pytest.raises(KeyError):
            mgr.update_tenant("missing", name="x")

    def test_delete_tenant(self):
        mgr = TenantManager()
        mgr.create_tenant("t1", "Acme")
        assert mgr.delete_tenant("t1") is True
        assert mgr.get_tenant("t1") is None
        assert mgr.delete_tenant("t1") is False

    def test_resolve_by_api_key(self):
        mgr = TenantManager()
        _, key = mgr.create_tenant("t1", "Acme")
        resolved = mgr.resolve_by_api_key(key)
        assert resolved is not None
        assert resolved.tenant_id == "t1"

    def test_resolve_bad_key_returns_none(self):
        mgr = TenantManager()
        mgr.create_tenant("t1", "Acme")
        assert mgr.resolve_by_api_key("totally-wrong-key") is None

    def test_resolve_disabled_tenant_returns_none(self):
        mgr = TenantManager()
        _, key = mgr.create_tenant("t1", "Acme")
        mgr.update_tenant("t1", enabled=False)
        assert mgr.resolve_by_api_key(key) is None

    def test_rotate_api_key(self):
        mgr = TenantManager()
        _, old_key = mgr.create_tenant("t1", "Acme")
        new_key = mgr.rotate_api_key("t1")
        assert new_key != old_key
        assert mgr.resolve_by_api_key(old_key) is None
        assert mgr.resolve_by_api_key(new_key).tenant_id == "t1"

    def test_rotate_nonexistent_raises(self):
        mgr = TenantManager()
        with pytest.raises(KeyError):
            mgr.rotate_api_key("missing")

    def test_get_effective_config(self):
        mgr = TenantManager()
        mgr.create_tenant("t1", "Acme", config_overrides={"ml_high": 0.95}, rate_limit=100)
        base = {"ml_high": 0.85, "ml_low": 0.3, "rate_limit": 30}
        effective = mgr.get_effective_config("t1", base)
        assert effective["ml_high"] == 0.95
        assert effective["ml_low"] == 0.3
        assert effective["rate_limit"] == 100

    def test_get_effective_config_missing_tenant(self):
        mgr = TenantManager()
        base = {"ml_high": 0.85}
        assert mgr.get_effective_config("missing", base) == base

    def test_api_key_not_stored_plaintext(self):
        mgr = TenantManager()
        tenant, key = mgr.create_tenant("t1", "Acme")
        # The stored hash should NOT equal the plaintext key
        assert tenant.api_key_hash != key
        assert tenant.api_key_hash == _hash_key(key, tenant.api_key_salt)

    def test_thread_safety(self):
        mgr = TenantManager()
        errors = []

        def create_many(prefix, count):
            try:
                for i in range(count):
                    mgr.create_tenant(f"{prefix}-{i}", f"Tenant {prefix}-{i}")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=create_many, args=(f"t{n}", 20))
            for n in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(mgr.list_tenants()) == 100


# ============================================================
# Password Hashing Tests
# ============================================================


class TestPasswordHashing:

    def test_hash_and_verify(self):
        hashed = _hash_password("correcthorse")
        assert _verify_password("correcthorse", hashed)
        assert not _verify_password("wrongpassword", hashed)

    def test_different_salts(self):
        h1 = _hash_password("same")
        h2 = _hash_password("same")
        # Different salts produce different hashes
        assert h1 != h2
        # Both still verify
        assert _verify_password("same", h1)
        assert _verify_password("same", h2)

    def test_malformed_hash_returns_false(self):
        assert _verify_password("anything", "nocolon") is False


# ============================================================
# RBACManager Tests
# ============================================================


class TestRBACManager:

    def test_create_user(self):
        rbac = RBACManager()
        user = rbac.create_user("u1", "alice", "s3cret", role="analyst")
        assert user.username == "alice"
        assert user.role == "analyst"
        assert user.password_hash != "s3cret"

    def test_create_duplicate_id_raises(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "pw")
        with pytest.raises(ValueError, match="already exists"):
            rbac.create_user("u1", "bob", "pw")

    def test_create_duplicate_username_raises(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "pw")
        with pytest.raises(ValueError, match="already taken"):
            rbac.create_user("u2", "alice", "pw2")

    def test_authenticate_success(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "s3cret")
        user = rbac.authenticate("alice", "s3cret")
        assert user is not None
        assert user.username == "alice"

    def test_authenticate_wrong_password(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "s3cret")
        assert rbac.authenticate("alice", "wrong") is None

    def test_authenticate_unknown_user(self):
        rbac = RBACManager()
        assert rbac.authenticate("nobody", "pw") is None

    def test_authenticate_disabled_user(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "s3cret")
        rbac.update_user("u1", enabled=False)
        assert rbac.authenticate("alice", "s3cret") is None

    def test_authorize_admin_has_all(self):
        rbac = RBACManager()
        user = rbac.create_user("u1", "admin", "pw", role="admin")
        for perm in Permission:
            assert rbac.authorize(user, perm)

    def test_authorize_viewer_limited(self):
        rbac = RBACManager()
        user = rbac.create_user("u1", "viewer", "pw", role="viewer")
        assert rbac.authorize(user, Permission.VIEW_SESSIONS)
        assert rbac.authorize(user, Permission.VIEW_METRICS)
        assert not rbac.authorize(user, Permission.ANALYZE)
        assert not rbac.authorize(user, Permission.MANAGE_TENANTS)

    def test_authorize_api_client(self):
        rbac = RBACManager()
        user = rbac.create_user("u1", "bot", "pw", role="api_client")
        assert rbac.authorize(user, Permission.ANALYZE)
        assert not rbac.authorize(user, Permission.VIEW_SESSIONS)
        assert not rbac.authorize(user, Permission.MANAGE_USERS)

    def test_authorize_analyst(self):
        rbac = RBACManager()
        user = rbac.create_user("u1", "analyst1", "pw", role="analyst")
        assert rbac.authorize(user, Permission.ANALYZE)
        assert rbac.authorize(user, Permission.VIEW_SESSIONS)
        assert rbac.authorize(user, Permission.EXPORT_DATA)
        assert not rbac.authorize(user, Permission.MANAGE_TENANTS)
        assert not rbac.authorize(user, Permission.MANAGE_USERS)

    def test_authorize_disabled_user_denied(self):
        rbac = RBACManager()
        user = rbac.create_user("u1", "alice", "pw", role="admin")
        user.enabled = False
        assert not rbac.authorize(user, Permission.ANALYZE)

    def test_custom_role(self):
        rbac = RBACManager()
        rbac.create_role("auditor", {Permission.VIEW_SESSIONS, Permission.EXPORT_DATA})
        user = rbac.create_user("u1", "alice", "pw", role="auditor")
        assert rbac.authorize(user, Permission.VIEW_SESSIONS)
        assert rbac.authorize(user, Permission.EXPORT_DATA)
        assert not rbac.authorize(user, Permission.ANALYZE)

    def test_list_roles(self):
        rbac = RBACManager()
        rbac.create_role("custom1", {Permission.ANALYZE})
        roles = rbac.list_roles()
        assert "admin" in roles
        assert "custom1" in roles

    def test_update_user_password(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "oldpw")
        rbac.update_user("u1", password="newpw")
        assert rbac.authenticate("alice", "oldpw") is None
        assert rbac.authenticate("alice", "newpw") is not None

    def test_update_user_username(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "pw")
        rbac.update_user("u1", username="alice2")
        assert rbac.authenticate("alice", "pw") is None
        assert rbac.authenticate("alice2", "pw") is not None

    def test_delete_user(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "pw")
        assert rbac.delete_user("u1") is True
        assert rbac.get_user("u1") is None
        assert rbac.delete_user("u1") is False

    def test_get_user_by_username(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "pw")
        assert rbac.get_user_by_username("alice").user_id == "u1"
        assert rbac.get_user_by_username("nobody") is None

    def test_thread_safety(self):
        rbac = RBACManager()
        errors = []

        def create_many(prefix, count):
            try:
                for i in range(count):
                    rbac.create_user(f"{prefix}-{i}", f"user-{prefix}-{i}", "pw")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=create_many, args=(f"g{n}", 20))
            for n in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(rbac.list_users()) == 100


# ============================================================
# Auth Middleware Tests (Flask)
# ============================================================


class TestAuthMiddleware:

    def _make_app(self, tenant_manager=None, rbac_manager=None, permission=None):
        """Create a minimal Flask app with require_auth."""
        from flask import Flask, g, jsonify
        from sentinel.auth_middleware import require_auth

        app = Flask(__name__)

        @app.route("/protected")
        @require_auth(
            tenant_manager=tenant_manager,
            rbac_manager=rbac_manager,
            permission=permission,
        )
        def protected():
            return jsonify({
                "tenant_id": g.tenant.tenant_id if g.tenant else None,
                "user": g.user.username if g.user else None,
            })

        return app

    def test_api_key_via_header(self):
        tm = TenantManager()
        _, key = tm.create_tenant("t1", "Acme")
        app = self._make_app(tenant_manager=tm)

        with app.test_client() as c:
            resp = c.get("/protected", headers={"X-API-Key": key})
            assert resp.status_code == 200
            assert resp.get_json()["tenant_id"] == "t1"

    def test_api_key_via_bearer(self):
        tm = TenantManager()
        _, key = tm.create_tenant("t1", "Acme")
        app = self._make_app(tenant_manager=tm)

        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Bearer {key}"})
            assert resp.status_code == 200
            assert resp.get_json()["tenant_id"] == "t1"

    def test_basic_auth(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "s3cret", role="admin")
        app = self._make_app(rbac_manager=rbac)

        creds = base64.b64encode(b"alice:s3cret").decode()
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Basic {creds}"})
            assert resp.status_code == 200
            assert resp.get_json()["user"] == "alice"

    def test_no_auth_returns_401(self):
        tm = TenantManager()
        app = self._make_app(tenant_manager=tm)

        with app.test_client() as c:
            resp = c.get("/protected")
            assert resp.status_code == 401

    def test_bad_api_key_returns_401(self):
        tm = TenantManager()
        tm.create_tenant("t1", "Acme")
        app = self._make_app(tenant_manager=tm)

        with app.test_client() as c:
            resp = c.get("/protected", headers={"X-API-Key": "wrong"})
            assert resp.status_code == 401

    def test_bad_basic_auth_returns_401(self):
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "s3cret")
        app = self._make_app(rbac_manager=rbac)

        creds = base64.b64encode(b"alice:wrong").decode()
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Basic {creds}"})
            assert resp.status_code == 401

    def test_permission_denied_returns_403(self):
        rbac = RBACManager()
        rbac.create_user("u1", "viewer1", "pw", role="viewer")
        app = self._make_app(rbac_manager=rbac, permission=Permission.MANAGE_TENANTS)

        creds = base64.b64encode(b"viewer1:pw").decode()
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Basic {creds}"})
            assert resp.status_code == 403

    def test_permission_granted(self):
        rbac = RBACManager()
        rbac.create_user("u1", "analyst1", "pw", role="analyst")
        app = self._make_app(rbac_manager=rbac, permission=Permission.ANALYZE)

        creds = base64.b64encode(b"analyst1:pw").decode()
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Basic {creds}"})
            assert resp.status_code == 200

    def test_no_managers_denies_by_default(self):
        """Secure default: no managers configured = auth denied."""
        app = self._make_app()

        with app.test_client() as c:
            resp = c.get("/protected")
            assert resp.status_code == 401

    def test_tenant_scoped_user(self):
        """Basic auth user with tenant_id resolves both user and tenant."""
        tm = TenantManager()
        tm.create_tenant("t1", "Acme")
        rbac = RBACManager()
        rbac.create_user("u1", "alice", "pw", role="analyst", tenant_id="t1")
        app = self._make_app(tenant_manager=tm, rbac_manager=rbac)

        creds = base64.b64encode(b"alice:pw").decode()
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Basic {creds}"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["tenant_id"] == "t1"
            assert data["user"] == "alice"


# ============================================================
# Lazy import from package root
# ============================================================


class TestPackageExports:

    def test_tenant_imports(self):
        from sentinel import Tenant, TenantManager
        assert Tenant is not None
        assert TenantManager is not None

    def test_rbac_imports(self):
        from sentinel import Permission, RBACManager, User
        assert Permission is not None
        assert RBACManager is not None
        assert User is not None

    def test_auth_imports(self):
        from sentinel import require_auth
        assert callable(require_auth)
