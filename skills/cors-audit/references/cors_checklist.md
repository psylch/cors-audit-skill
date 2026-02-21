# CORS Audit Checklist

Detailed per-item checklist for auditing CORS configuration. Each item includes pass/fail criteria and remediation guidance.

---

## 1. Single-Layer Rule

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 1.1 | Count layers that set `Access-Control-Allow-Origin` | Exactly 1 layer sets this header | Critical |
| 1.2 | If gateway + backend both set CORS headers | Backend CORS disabled in production OR gateway strips upstream headers | Critical |
| 1.3 | CDN/edge layer checked for CORS header injection | CDN does not add its own CORS headers, or is the designated single layer | Critical |

**How to verify:**
```bash
# Check actual response headers (look for duplicates)
curl -v -H "Origin: https://your-frontend.com" https://your-api.com/api/endpoint 2>&1 | grep -i access-control
```

If two `Access-Control-Allow-Origin` lines appear, the single-layer rule is violated.

---

## 2. Origin Policy

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 2.1 | Production uses specific origin, not `*` | Origin is an explicit domain or dynamic reflection | Warning |
| 2.2 | `*` is NOT combined with `Credentials: true` | If credentials required, origin must be specific | Critical |
| 2.3 | Origin matches actual frontend domain | The allowed origin matches what the browser sends as `Origin` | Critical |
| 2.4 | Micro-app: origin is host domain, not app domain | If embedded, the host app's domain is in the allowlist | Critical |
| 2.5 | Regex patterns are correct (if used) | Test regex against all expected origins AND verify it rejects unexpected ones | Warning |

**Regex testing example:**
```python
import re
pattern = r"^https://.*\.example\.com$"
# Should match
assert re.match(pattern, "https://app.example.com")
assert re.match(pattern, "https://staging.example.com")
# Should NOT match
assert not re.match(pattern, "https://evil-example.com")
assert not re.match(pattern, "https://example.com")  # no subdomain — check if this is intended
```

---

## 3. Preflight Handling

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 3.1 | OPTIONS requests return 2xx (typically 204) | Preflight responses have status 204 with CORS headers | Critical |
| 3.2 | OPTIONS handler includes all required CORS headers | `Allow-Origin`, `Allow-Methods`, `Allow-Headers` all present | Critical |
| 3.3 | `Access-Control-Max-Age` is set | Value present (recommended: 86400 = 24 hours) | Warning |
| 3.4 | OPTIONS requests do not hit backend business logic | Gateway or framework handles OPTIONS before routing to handlers | Info |

**How to verify:**
```bash
# Send a preflight request
curl -v -X OPTIONS \
  -H "Origin: https://your-frontend.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  https://your-api.com/api/endpoint 2>&1 | grep -E "(< HTTP|access-control)"
```

Expected: HTTP 204, all `Access-Control-*` headers present.

---

## 4. Credentials

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 4.1 | If frontend sends cookies/auth headers | `Access-Control-Allow-Credentials: true` is set | Critical |
| 4.2 | If credentials enabled, origin is not `*` | Specific origin or dynamic reflection used | Critical |
| 4.3 | Frontend fetch includes `credentials` option | `fetch(url, { credentials: 'include' })` if cookies needed | Critical |

---

## 5. Headers and Methods

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 5.1 | `Allow-Methods` includes all HTTP methods used | All methods the frontend actually calls (GET, POST, PUT, DELETE, PATCH) are listed | Critical |
| 5.2 | `Allow-Headers` includes all custom request headers | Headers like `Authorization`, `Content-Type`, `X-API-Key` are listed | Critical |
| 5.3 | `Allow-Headers` is not overly broad unnecessarily | Review if `*` is appropriate or if specific headers should be listed | Info |

---

## 6. Frontend Configuration

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 6.1 | API base URL is correct for each environment | Dev: `localhost`, Prod: gateway domain or relative path | Critical |
| 6.2 | Env var fallback does not default to `localhost` in prod | Use `??` (nullish coalescing), not `\|\|` (logical OR) for fallback | Critical |
| 6.3 | Micro-app uses absolute URL for API | Not relative path (which resolves to host domain) | Critical |
| 6.4 | No hardcoded API URLs in source code | API base URL comes from environment configuration | Warning |

**Fallback anti-pattern:**
```typescript
// BAD: empty string is falsy, falls through to localhost in production
const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// GOOD: only falls back if env var is truly undefined/null
const API = import.meta.env.VITE_API_URL ?? '';
```

---

## 7. Environment Separation

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 7.1 | Dev and prod have different CORS strategies | Dev: backend CORS enabled. Prod: gateway CORS only | Warning |
| 7.2 | CORS toggle exists for backend | Env var like `ENABLE_CORS` controls backend CORS middleware | Warning |
| 7.3 | Dev env does not leak into production | No `localhost` origins in production config | Critical |
| 7.4 | Staging environment has appropriate CORS | Staging uses its own origin, not prod origin | Info |

---

## 8. Security

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 8.1 | No wildcard `*` origin in production with credentials | Self-explanatory | Critical |
| 8.2 | Origin regex does not accidentally match malicious domains | e.g., `.*example.com` should not match `evil-example.com` | Warning |
| 8.3 | CORS is not used as sole auth mechanism | CORS restricts browsers, not server-to-server calls | Info |
| 8.4 | Sensitive endpoints have additional auth beyond CORS | API keys, JWT, session cookies for write operations | Info |

---

## 9. Consistency (Multi-Service)

| # | Check | Pass Criteria | Severity |
|---|-------|--------------|----------|
| 9.1 | All micro-apps/services use the same CORS pattern | Same gateway config structure, same origin policy approach | Warning |
| 9.2 | Backend CORS toggle naming is consistent | All backends use the same env var (e.g., `ENABLE_CORS`) | Info |
| 9.3 | Documentation matches actual configuration | API docs reflect the actual CORS behavior | Warning |

---

## Audit Summary Template

After completing the checklist, fill in this summary:

```
## CORS Audit Summary

**Project:** [name]
**Date:** [date]
**Architecture:** [Pattern 1-5 from architecture_patterns.md]
**CORS Authority:** [Gateway / Backend / Edge]

### Layer Status
| Layer    | CORS Active? | Origin Policy       | Credentials | Preflight |
|----------|-------------|---------------------|-------------|-----------|
| Gateway  |             |                     |             |           |
| Backend  |             |                     |             |           |
| CDN/Edge |             |                     |             |           |

### Issues Found
| # | Severity | Check | Description | Remediation |
|---|----------|-------|-------------|-------------|
|   |          |       |             |             |

### Recommendations
1. ...
2. ...
```
