"""
Sentinel - Role-Based Access Control (RBAC)
Thread-safe user management with password hashing and permission checks.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass, field


class Permission(enum.Enum):
    """Permissions that can be assigned to roles."""

    ANALYZE = "analyze"
    VIEW_SESSIONS = "view_sessions"
    MANAGE_SESSIONS = "manage_sessions"
    VIEW_METRICS = "view_metrics"
    VIEW_DASHBOARD = "view_dashboard"
    MANAGE_TENANTS = "manage_tenants"
    MANAGE_USERS = "manage_users"
    MANAGE_CONFIG = "manage_config"
    EXPORT_DATA = "export_data"


# ---- Built-in role definitions ----

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "admin": frozenset(Permission),
    "analyst": frozenset(
        {
            Permission.ANALYZE,
            Permission.VIEW_SESSIONS,
            Permission.VIEW_METRICS,
            Permission.VIEW_DASHBOARD,
            Permission.EXPORT_DATA,
        }
    ),
    "viewer": frozenset(
        {
            Permission.VIEW_SESSIONS,
            Permission.VIEW_METRICS,
            Permission.VIEW_DASHBOARD,
        }
    ),
    "api_client": frozenset(
        {
            Permission.ANALYZE,
        }
    ),
}


def _hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 (600k iterations).

    Returns ``salt_hex:hash_hex``.
    """
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return salt.hex() + ":" + dk.hex()


def _verify_password(password: str, stored: str) -> bool:
    """Timing-safe verification of a password against a stored hash."""
    try:
        salt_hex, hash_hex = stored.split(":", 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return hmac.compare_digest(dk.hex(), hash_hex)


@dataclass
class User:
    """A user in the RBAC system."""

    user_id: str
    username: str
    password_hash: str = ""
    role: str = "viewer"
    tenant_id: str | None = None
    enabled: bool = True
    created_at: float = field(default_factory=time.time)


class RBACManager:
    """
    Manages users, roles, and permissions.

    Thread-safe with RLock on all shared state.

    Account lockout: after ``max_failed_attempts`` (default 5) failed
    login attempts within ``lockout_window_seconds`` (default 900 = 15 min),
    the account is locked for the remainder of the window.

    Usage::

        rbac = RBACManager()
        user = rbac.create_user("u1", "alice", "s3cret", role="analyst")
        authed = rbac.authenticate("alice", "s3cret")
        assert rbac.authorize(authed, Permission.ANALYZE)
    """

    def __init__(self, max_failed_attempts: int = 5, lockout_window_seconds: int = 900):
        self._users: dict[str, User] = {}
        self._username_index: dict[str, str] = {}  # username -> user_id
        self._custom_roles: dict[str, frozenset[Permission]] = {}
        self._lock = threading.RLock()
        # Account lockout tracking: username -> list of failure timestamps
        self._failed_attempts: dict[str, list] = {}
        self._max_failed_attempts = max_failed_attempts
        self._lockout_window = lockout_window_seconds

    # ---- Role management ----

    def get_role_permissions(self, role: str) -> frozenset[Permission]:
        """Return the permission set for a role name."""
        with self._lock:
            if role in self._custom_roles:
                return self._custom_roles[role]
        return ROLE_PERMISSIONS.get(role, frozenset())

    def create_role(self, name: str, permissions: set[Permission]) -> None:
        """Create a custom role with the given permissions."""
        with self._lock:
            self._custom_roles[name] = frozenset(permissions)

    def list_roles(self) -> dict[str, frozenset[Permission]]:
        """Return all roles (built-in + custom)."""
        with self._lock:
            merged = dict(ROLE_PERMISSIONS)
            merged.update(self._custom_roles)
            return merged

    # ---- User CRUD ----

    def create_user(
        self,
        user_id: str,
        username: str,
        password: str,
        role: str = "viewer",
        tenant_id: str | None = None,
    ) -> User:
        """Create a new user.  Password is hashed immediately."""
        pw_hash = _hash_password(password)
        user = User(
            user_id=user_id,
            username=username,
            password_hash=pw_hash,
            role=role,
            tenant_id=tenant_id,
        )

        with self._lock:
            if user_id in self._users:
                raise ValueError(f"User {user_id!r} already exists")
            if username in self._username_index:
                raise ValueError(f"Username {username!r} already taken")
            self._users[user_id] = user
            self._username_index[username] = user_id

        return user

    def get_user(self, user_id: str) -> User | None:
        with self._lock:
            return self._users.get(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        with self._lock:
            uid = self._username_index.get(username)
            if uid is None:
                return None
            return self._users.get(uid)

    def list_users(self) -> list:
        with self._lock:
            return list(self._users.values())

    # Role hierarchy for privilege escalation checks (higher index = more privilege)
    _ROLE_HIERARCHY = ["api_client", "viewer", "analyst", "admin"]

    def update_user(self, user_id: str, **fields) -> User:
        """Update user fields.

        .. warning::
            If *role* is changed, the new role must not be higher in the
            hierarchy than the current role (prevents privilege escalation).
            To promote a user to a higher role, use an admin-authenticated
            endpoint that explicitly bypasses this guard.
        """
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise KeyError(f"User {user_id!r} not found")
            if "password" in fields:
                user.password_hash = _hash_password(fields.pop("password"))
            if "username" in fields and fields["username"] != user.username:
                new_name = fields["username"]
                if new_name in self._username_index:
                    raise ValueError(f"Username {new_name!r} already taken")
                del self._username_index[user.username]
                self._username_index[new_name] = user_id
                user.username = new_name
                del fields["username"]
            # Role escalation guard: reject if new role is higher than current
            if "role" in fields:
                new_role = fields["role"]
                cur_idx = (
                    self._ROLE_HIERARCHY.index(user.role)
                    if user.role in self._ROLE_HIERARCHY
                    else -1
                )
                new_idx = (
                    self._ROLE_HIERARCHY.index(new_role) if new_role in self._ROLE_HIERARCHY else -1
                )
                if new_idx > cur_idx:
                    raise PermissionError(
                        f"Cannot escalate role from {user.role!r} to {new_role!r} -- "
                        "use an admin endpoint for promotions"
                    )
                user.role = new_role
                del fields["role"]
            for k, v in fields.items():
                if hasattr(user, k) and k not in ("user_id", "password_hash", "created_at"):
                    setattr(user, k, v)
            return user

    def delete_user(self, user_id: str) -> bool:
        with self._lock:
            user = self._users.pop(user_id, None)
            if user is None:
                return False
            self._username_index.pop(user.username, None)
            return True

    # ---- Account lockout helpers ----

    def _prune_failed_attempts(self, username: str) -> None:
        """Remove failure records older than the lockout window (caller holds lock)."""
        cutoff = time.time() - self._lockout_window
        attempts = self._failed_attempts.get(username)
        if attempts:
            self._failed_attempts[username] = [t for t in attempts if t > cutoff]

    def _is_locked_out(self, username: str) -> bool:
        """Check if the account is currently locked (caller holds lock)."""
        self._prune_failed_attempts(username)
        attempts = self._failed_attempts.get(username, [])
        return len(attempts) >= self._max_failed_attempts

    def _record_failure(self, username: str) -> None:
        """Record a failed login attempt (caller holds lock)."""
        self._failed_attempts.setdefault(username, []).append(time.time())

    def _clear_failures(self, username: str) -> None:
        """Clear failure records on successful auth (caller holds lock)."""
        self._failed_attempts.pop(username, None)

    def is_locked_out(self, username: str) -> bool:
        """Public check: is the account currently locked?"""
        with self._lock:
            return self._is_locked_out(username)

    # ---- Authentication ----

    def authenticate(self, username: str, password: str) -> User | None:
        """Authenticate by username + password.

        Returns the User on success, None on failure.
        Accounts are locked after ``max_failed_attempts`` failures
        within the lockout window.
        """
        with self._lock:
            # Check lockout before doing any work
            if self._is_locked_out(username):
                # Still do a dummy hash to prevent timing leaks
                _hash_password(password)
                return None

            uid = self._username_index.get(username)
            if uid is None:
                # Perform a dummy hash to prevent timing leaks
                _hash_password(password)
                self._record_failure(username)
                return None
            user = self._users.get(uid)

        if user is None or not user.enabled:
            _hash_password(password)
            with self._lock:
                self._record_failure(username)
            return None

        if _verify_password(password, user.password_hash):
            with self._lock:
                self._clear_failures(username)
            return user

        with self._lock:
            self._record_failure(username)
        return None

    # ---- Authorization ----

    def authorize(self, user: User, permission: Permission) -> bool:
        """Check whether *user* has *permission*."""
        if not user.enabled:
            return False
        perms = self.get_role_permissions(user.role)
        return permission in perms
