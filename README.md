# cors-audit-skill

[中文文档](README.zh.md)

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skill that performs architecture-level CORS audits. Unlike configuration-only tools, this skill audits the **entire request path** — gateway, backend, and frontend — to catch issues that single-layer tools miss.

Born from real production debugging: duplicate `Access-Control-Allow-Origin` headers from Caddy + FastAPI, broken micro-app embedding, and environment-specific misconfigurations.

| What it covers | How |
|----------------|-----|
| **Duplicate CORS headers** | Detects when gateway + backend both set headers (the #1 CORS bug) |
| **Gateway configs** | Validates Caddyfile, nginx.conf for CORS issues |
| **Micro-app embedding** | Qiankun / single-spa origin and URL path pitfalls |
| **Environment separation** | Dev vs production CORS strategy audit |
| **Multi-origin APIs** | Dynamic origin reflection patterns |
| **Automated validation** | Bundled Python script tests live endpoints and static configs |

## Installation

### Via `npx skills` (recommended)

```bash
npx skills add psylch/cors-audit-skill -g -y
```

### Via Plugin Marketplace

In Claude Code:

```
/plugin marketplace add psylch/cors-audit-skill
/plugin install cors-audit@psylch-cors-audit-skill
```

### Manual Install

```bash
git clone https://github.com/psylch/cors-audit-skill.git ~/.claude/skills/cors-audit-skill
```

Restart Claude Code after installation.

## Prerequisites

- **Python 3.7+** (for the validation script, uses stdlib only — no pip install needed)
- A web project with CORS to audit

## Usage

In Claude Code, use any of these trigger phrases:

```
audit CORS configuration
check CORS headers
diagnose cross-origin issue
CORS 走查
跨域问题排查
```

The skill guides Claude through a 6-phase audit process:

1. **Architecture Discovery** — identify all network layers and classify the setup
2. **Configuration Collection** — gather CORS config from every layer + run static validation
3. **Single-Layer Rule** — verify only one layer sets CORS headers + live duplicate detection
4. **Best Practice Validation** — check origin policy, preflight, credentials, headers
5. **Environment Validation** — dev/prod/micro-app specific checks
6. **Report** — severity-classified findings with remediation

## Validation Script

The bundled `scripts/validate_cors.py` automates key checks:

```bash
# Test a live endpoint (detects duplicate headers, preflight issues, origin policy)
python scripts/validate_cors.py --url https://api.example.com/health --origin https://app.example.com

# Validate a static config file (Caddyfile, nginx.conf, or JSON policy)
python scripts/validate_cors.py --config path/to/Caddyfile

# Batch test multiple endpoints
python scripts/validate_cors.py --url-file endpoints.txt --origin https://app.example.com

# JSON output for CI integration
python scripts/validate_cors.py --url https://api.example.com/health --origin https://app.example.com --format json --output report.json
```

Exit codes: `0` = pass, `2` = critical issues found. Zero external dependencies.

## Architecture Patterns Covered

| Pattern | Example | CORS Strategy |
|---------|---------|---------------|
| **Same-origin** | Monolith serving HTML + API | No CORS needed |
| **Simple cross-origin** | `app.com` → `api.com` | Backend handles CORS |
| **Gateway-proxied** | Caddy/Nginx in front of both | Gateway handles CORS, backend disabled |
| **Micro-app embedded** | Qiankun app in host site | Gateway with host domain as allowed origin |
| **Multi-consumer API** | Multiple frontends → one API | Dynamic origin reflection |

## File Structure

```
cors-audit-skill/
├── .claude-plugin/
│   ├── marketplace.json
│   └── plugin.json
├── skills/
│   └── cors-audit/
│       ├── SKILL.md                        # 6-phase audit process
│       ├── scripts/
│       │   └── validate_cors.py            # Automated validator (stdlib only)
│       └── references/
│           ├── architecture_patterns.md    # 5 patterns with config examples
│           └── cors_checklist.md           # 30+ audit items with pass/fail criteria
├── README.md
├── README.zh.md
└── LICENSE
```

## License

MIT
