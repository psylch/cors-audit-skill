---
name: cors-audit
description: "This skill performs a comprehensive CORS (Cross-Origin Resource Sharing) audit on web projects. It should be used when diagnosing CORS errors, setting up CORS for new projects, reviewing CORS configuration after deployment issues, or validating that CORS is handled correctly across all layers (gateway, backend, frontend). Covers standard frontend-backend setups, micro-app architectures (Qiankun, single-spa), and multi-origin dynamic-origin scenarios."
---

# CORS Audit

Perform a systematic CORS configuration audit across all layers of a web project. Identify misconfigurations, redundant headers, and security issues before they cause production problems.

## Bundled Resources

- `scripts/validate_cors.py` — Automated CORS validator (Python stdlib, no dependencies)
- `references/cors_checklist.md` — Detailed per-item audit checklist with pass/fail criteria
- `references/architecture_patterns.md` — CORS strategy for each architecture type with configuration examples

## When to Use

- CORS errors appear in browser console after deployment or configuration changes
- Setting up a new project with cross-origin API calls
- Reviewing existing CORS setup for correctness and security
- Migrating from direct API access to gateway-proxied architecture
- Embedding micro-apps (Qiankun, single-spa, Module Federation) into a host application

## Audit Process

### Phase 1: Architecture Discovery

Before examining any configuration, determine the project's architecture type:

1. **Identify all network layers** between browser and backend:
   - Reverse proxy / API gateway (Caddy, Nginx, Traefik, Cloudflare)
   - Backend framework (FastAPI, Express, Spring Boot, etc.)
   - CDN or edge functions

2. **Classify the architecture** — reference `references/architecture_patterns.md` for details:
   - **Same-origin**: Frontend and API served from the same domain — CORS not needed
   - **Simple cross-origin**: Frontend on domain A, API on domain B
   - **Gateway-proxied**: Frontend and API behind a single gateway domain
   - **Micro-app embedded**: App embedded in a host application on a different domain
   - **Multi-consumer API**: API consumed by multiple known domains

3. **Map all request flows** — trace from browser to backend:
   - What domain does the browser request originate from? (the `Origin` header)
   - What domain does the request target?
   - Does the request pass through a gateway/proxy?
   - Are credentials (cookies, auth headers) required?

### Phase 2: Configuration Collection and Static Validation

Collect CORS-related configuration from every layer. For each layer, document:
- Where CORS headers are set
- What `Access-Control-Allow-Origin` value is used
- Whether `Access-Control-Allow-Credentials` is set
- How preflight (OPTIONS) requests are handled

**Layer checklist:**

| Layer | What to check |
|-------|---------------|
| Gateway/Proxy | Config file (Caddyfile, nginx.conf, etc.) — CORS headers, OPTIONS handling |
| Backend | CORS middleware config — origin lists, regex patterns, credential flags |
| Frontend | API base URL config — same-origin, relative path, or cross-origin absolute URL? |
| Environment vars | Different CORS settings per environment (dev/staging/production)? |

**Run static config validation** on each gateway/proxy config file found:

```bash
python scripts/validate_cors.py --config path/to/Caddyfile
python scripts/validate_cors.py --config path/to/nginx.conf
```

This detects wildcard+credentials conflicts, missing preflight handlers, dual-layer CORS signals (`header_down`/`proxy_hide_header`), and Nginx scope inheritance issues.

### Phase 3: Apply the Single-Layer Rule

**The #1 CORS best practice: CORS headers must be set by exactly ONE layer.**

Duplicate headers are the most common CORS bug. When both a gateway and backend add `Access-Control-Allow-Origin`, the browser receives two values and rejects the response.

Audit steps:

1. **Count CORS-setting layers** — if more than one layer adds CORS headers, flag it immediately
2. **Choose the authoritative layer** based on architecture:
   - Gateway-proxied → gateway handles CORS, backend CORS disabled in production
   - No gateway → backend handles CORS
   - CDN/edge → edge handles CORS if it terminates the request
3. **Verify non-authoritative layers are silent** — they must not add any `Access-Control-*` headers
4. **If dual layers are unavoidable** (e.g., cannot modify backend), the gateway must strip upstream CORS headers:
   - Caddy: `header_down -Access-Control-Allow-Origin`
   - Nginx: `proxy_hide_header Access-Control-Allow-Origin;`
   - Note: stripping is a workaround, not best practice — prefer disabling at source

**Verify the single-layer rule on live endpoints** — this is the most reliable check because it catches headers added by any layer, including ones not visible in static config:

```bash
python scripts/validate_cors.py --url https://your-api.com/health --origin https://your-frontend.com
```

The script uses raw HTTP connections to detect duplicate `Access-Control-Allow-Origin` headers that browsers would reject. This is the check that catches the gateway+backend double-header bug.

### Phase 4: Validate Configuration Against Best Practices

Reference `references/cors_checklist.md` for the full per-item checklist. Key validations:

**Origin policy:**
- Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — browsers reject this
- Prefer specific origins over wildcards in production
- For multiple origins, implement dynamic origin reflection (check request Origin against whitelist, echo back the matched origin)

**Preflight handling:**
- OPTIONS requests must return 204 (No Content) with all required CORS headers
- Include `Access-Control-Max-Age` to reduce preflight frequency
- Verify the gateway or backend actually handles OPTIONS — some frameworks ignore it by default

**Credentials:**
- If the frontend sends cookies or `Authorization` headers, `Access-Control-Allow-Credentials: true` is required
- With credentials, `Access-Control-Allow-Origin` must be a specific origin (not `*`)

**Headers and methods:**
- `Access-Control-Allow-Headers` must include all custom headers the frontend sends
- `Access-Control-Allow-Methods` must include all HTTP methods used

### Phase 5: Environment-Specific Validation

1. **Development environment:**
   - Backend CORS should be enabled (e.g., `ENABLE_CORS=true`) since there is no gateway
   - Frontend API base URL should point to `localhost` backend
   - Wildcard origins are acceptable for local dev

2. **Production environment:**
   - If using a gateway, backend CORS should be disabled
   - Frontend API base URL should route through the gateway (relative path or gateway domain)
   - Origins must be explicit, not wildcards

3. **Micro-app / embedded environment:**
   - The `Origin` header will be the host application's domain, not the micro-app's domain
   - The gateway must allow the host domain in `Access-Control-Allow-Origin`
   - Frontend API base URL must be an absolute URL to the gateway (relative paths resolve to the host domain, causing 404s)

**For production endpoints, run a full live validation** to confirm all the above in the real environment:

```bash
# Single endpoint
python scripts/validate_cors.py --url https://your-api.com/api/health --origin https://your-frontend.com

# Batch: create an endpoints.txt with one URL per line, then:
python scripts/validate_cors.py --url-file endpoints.txt --origin https://your-frontend.com
```

For micro-app scenarios, test with **both** the standalone origin and the host application origin:

```bash
# Standalone access
python scripts/validate_cors.py --url https://micro.example.com/api/health --origin https://micro.example.com

# Embedded access (this is the one that usually breaks)
python scripts/validate_cors.py --url https://micro.example.com/api/health --origin https://host-app.example.com
```

### Phase 6: Report Findings

Produce a summary table:

```
| Layer    | CORS Active? | Origin Policy         | Credentials | Issues |
|----------|--------------|-----------------------|-------------|--------|
| Gateway  | Yes          | https://example.com   | true        | None   |
| Backend  | No (prod)    | N/A                   | N/A         | None   |
| Frontend | N/A          | Requests via gateway  | N/A         | None   |
```

Classify issues by severity:
- **Critical**: Duplicate CORS headers, `*` with credentials, missing CORS entirely
- **Warning**: Wildcards in production, missing `Access-Control-Max-Age`, overly broad `Allow-Headers`
- **Info**: Suggestions for simplification or consistency

**Generate a JSON report for archival or CI integration:**

```bash
python scripts/validate_cors.py --url https://your-api.com/api/health --origin https://your-frontend.com --format json --output cors-report.json
```

Exit codes: `0` = pass, `2` = critical issues found. Use this in CI pipelines to fail builds on CORS regressions.

## Common Pitfalls Quick Reference

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| "multiple values `*, https://x.com`" | Two layers both add Origin header | Apply single-layer rule (Phase 3) |
| "No Access-Control-Allow-Origin header" | CORS not configured for this origin | Add origin to allowlist |
| Preflight blocked by CORS | OPTIONS not handled | Add OPTIONS handler returning 204 |
| Request to `localhost` from production | Frontend API URL not set for prod | Set API base URL to gateway domain |
| 404 on API when embedded as micro-app | Relative path resolves to host domain | Use absolute URL to gateway |
| Works standalone, fails when embedded | Origin is host domain, not app domain | Allow host domain in CORS config |
| Server-to-server calls unaffected | CORS is browser-only | Investigate auth/network issues instead |

## Script Reference

`scripts/validate_cors.py` — zero-dependency Python script for automated CORS validation.

**Modes:**

| Mode | Command | What it does |
|------|---------|-------------|
| Live endpoint | `--url URL --origin ORIGIN` | Sends OPTIONS + GET, checks duplicate headers, preflight, origin policy |
| Batch endpoints | `--url-file FILE --origin ORIGIN` | Same as above, one URL per line (skip blanks and #comments) |
| Static config | `--config FILE` | Parses Caddyfile / nginx.conf / JSON for misconfigurations |

**Options:**

| Flag | Purpose |
|------|---------|
| `--format json` | Output structured JSON instead of text |
| `--output FILE` | Write report to file instead of stdout |

**Exit codes:** `0` = pass, `2` = critical issues found.
