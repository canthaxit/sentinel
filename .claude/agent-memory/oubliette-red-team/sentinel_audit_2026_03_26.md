---
name: Oubliette Shield Security Audit - March 2026
description: Comprehensive red team assessment of oubliette-shield v1.0.0 at ~/.local/bin, 29 findings (4 CRITICAL, 7 HIGH, 10 MEDIUM, 5 LOW, 3 INFO)
type: project
---

## Oubliette Shield Red Team Assessment (2026-03-26)

**Scope:** oubliette-shield v1.0.0 at C:\Users\jimmy\.local\bin
**Findings:** 29 total (4C / 7H / 10M / 5L / 3I)

### Critical Findings
1. **Client-controlled session_id in /shield/analyze** (CWE-807) -- attacker rotates session_id to defeat multi-turn detection entirely
2. **.env not in .gitignore** (CWE-200) -- API keys could be committed to git
3. **IP spoofing behind proxy** (CWE-346) -- no ProxyFix middleware, rate limiting and IP attribution broken behind reverse proxy
4. **Pattern detector missing NFKD normalization** (CWE-436) -- homoglyph attacks bypass pattern_detector.py (pre_filter.py normalizes but pattern_detector.py does not)

### Key Architectural Observations
- Pipeline order: sanitize -> detect means HTML tag splitting can fragment attack patterns before detection
- contains_honey_token in API response is a detection oracle
- Timing side channel: 1.5s artificial delay on MALICIOUS only
- fail_open env var could disable all detection if environment is compromised
- No brute force protection on RBAC authentication
- SQL queries all use parameterized statements (good)
- PBKDF2 with 600K iterations for password/key hashing (good)
- hmac.compare_digest used consistently (good)

### Attack Path
session_id rotation -> homoglyph evasion -> LLM judge prompt injection -> undetected bypass

**Why:** This is the primary product's security -- findings here directly undermine the value proposition.
**How to apply:** When reviewing fixes, verify that session_id is server-derived, pattern_detector uses NFKD, and contains_honey_token is removed from responses.
