---
name: sentinel_audit_2026_03_26
description: Full red team audit of Sentinel AI firewall - 19 findings across CRITICAL/HIGH/MEDIUM/LOW severity
type: project
---

# Sentinel Red Team Assessment - March 26, 2026

## Audit Scope
- Full codebase: sentinel/ package, app.py, storage, MCP layer
- Prior 7 HIGH fixes verified: PBKDF2, SSRF, path traversal, log sanitization, unicode normalization, dead code removal
- New findings: 19 total (1 CRITICAL, 5 HIGH, 8 MEDIUM, 4 LOW, 1 INFO)

## Key Architecture Notes
- Flask app (app.py) + Shield detection pipeline (sentinel/ package)
- FastAPI middleware available (sentinel/fastapi.py)
- Storage: SQLite with WAL, parameterized queries
- Auth: API key (HMAC comparison) + optional RBAC + optional tenant mgmt
- MCP layer: MCPGuard + HoneyToolRegistry + mcp_scanner
- Session: in-memory dict with RLock, optional SQLite persistence

## Critical Findings
1. Default pepper in tenant.py line 19 - hardcoded "sentinel-default-pepper-change-me"
2. SSRF TOCTOU in ml_client.py - DNS resolution at init time only, not at request time
3. Auth bypass: API key auth disabled if SENTINEL_API_KEY is empty string
4. Honey tool detectability: deterministic tool names, `random` module (non-CSPRNG)
5. Tenant config_overrides allow arbitrary key injection via update_tenant

## Fixes Already Verified (Prior 7 HIGH)
- PBKDF2 with 600k iterations + salt + pepper: IMPLEMENTED
- SSRF blocklist + DNS resolution: IMPLEMENTED (but TOCTOU gap remains)
- Path traversal in drift_monitor: IMPLEMENTED (allowlist + resolve)
- Log sanitization: IMPLEMENTED (_sanitize_for_log)
- Unicode normalization: IMPLEMENTED (NFKC)
- hmac.compare_digest for timing safety: IMPLEMENTED
