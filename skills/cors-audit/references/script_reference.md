# Script Reference

`scripts/validate_cors.py` — zero-dependency Python script for automated CORS validation.

## Subcommands

| Subcommand | What it does |
|------------|-------------|
| `preflight` | Check runtime dependencies (Python version). Returns standard preflight JSON. |
| `validate` | Run CORS validation on endpoints or config files. |

## Validate Modes

| Mode | Command | What it does |
|------|---------|-------------|
| Live endpoint | `validate --url URL --origin ORIGIN` | Sends OPTIONS + GET, checks duplicate headers, preflight, origin policy |
| Batch endpoints | `validate --url-file FILE --origin ORIGIN` | Same as above, one URL per line (skip blanks and #comments) |
| Static config | `validate --config FILE` | Parses Caddyfile / nginx.conf / JSON for misconfigurations |

## Options (validate subcommand)

| Flag | Purpose |
|------|---------|
| `--format json` | Detailed JSON output with full findings (default) |
| `--format concise` | JSON summary only — finding counts by severity, no full findings |
| `--format text` | Human-readable text report |
| `--limit N` | Cap the number of findings returned in JSON output |
| `--output FILE` | Write report to file instead of stdout |

## Exit Codes

`0` = success (audit completed), `1` = recoverable runtime error, `2` = unrecoverable runtime error. Audit finding severity is in the JSON `summary` field, not the exit code.

## Examples

```bash
# Preflight check
python scripts/validate_cors.py preflight

# Static config validation
python scripts/validate_cors.py validate --config path/to/Caddyfile
python scripts/validate_cors.py validate --config path/to/nginx.conf

# Live endpoint validation
python scripts/validate_cors.py validate --url https://your-api.com/api/health --origin https://your-frontend.com

# Batch endpoints
python scripts/validate_cors.py validate --url-file endpoints.txt --origin https://your-frontend.com

# Concise summary
python scripts/validate_cors.py validate --url https://your-api.com/api/health --origin https://your-frontend.com --format concise

# Save to file
python scripts/validate_cors.py validate --url https://your-api.com/api/health --origin https://your-frontend.com --output cors-report.json

# Limit findings
python scripts/validate_cors.py validate --url https://your-api.com/api/health --origin https://your-frontend.com --limit 10
```

## Micro-app Testing

For micro-app scenarios, test with **both** the standalone origin and the host application origin:

```bash
# Standalone access
python scripts/validate_cors.py validate --url https://micro.example.com/api/health --origin https://micro.example.com

# Embedded access (this is the one that usually breaks)
python scripts/validate_cors.py validate --url https://micro.example.com/api/health --origin https://host-app.example.com
```
