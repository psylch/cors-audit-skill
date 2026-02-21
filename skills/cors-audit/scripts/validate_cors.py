#!/usr/bin/env python3
"""CORS configuration validator for live endpoints and static config files.

Usage:
    # Preflight check
    python validate_cors.py preflight

    # Validate a live endpoint (JSON output by default)
    python validate_cors.py validate --url https://api.example.com/api/health --origin https://app.example.com

    # Validate multiple endpoints from a file
    python validate_cors.py validate --url-file endpoints.txt --origin https://app.example.com

    # Validate a static config (Caddyfile, nginx.conf, or JSON policy)
    python validate_cors.py validate --config Caddyfile

    # Text output for humans
    python validate_cors.py validate --url https://api.example.com/api/health --origin https://app.example.com --format text

    # Concise JSON (summary only, no full findings)
    python validate_cors.py validate --url https://api.example.com/api/health --origin https://app.example.com --format concise

    # Limit number of findings returned
    python validate_cors.py validate --url https://api.example.com/api/health --origin https://app.example.com --limit 5
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Finding:
    severity: str
    check: str
    message: str
    details: str = ""


@dataclass
class EndpointResult:
    url: str
    origin: str
    findings: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    preflight_headers: dict = field(default_factory=dict)
    preflight_status: int = 0
    request_status: int = 0


@dataclass
class ConfigResult:
    file: str
    config_type: str
    findings: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def emit_error(error: str, hint: str, recoverable: bool, exit_code: int):
    """Print a JSON error to stderr and exit with the given code."""
    print(json.dumps({
        "error": error,
        "hint": hint,
        "recoverable": recoverable,
    }), file=sys.stderr)
    sys.exit(exit_code)


def _count_severities(findings: list) -> dict:
    """Count findings by severity level."""
    counts = {"critical": 0, "warning": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _make_hint(counts: dict) -> str:
    """Generate a human-readable hint from severity counts."""
    parts = []
    if counts["critical"] > 0:
        parts.append(f"{counts['critical']} critical")
    if counts["warning"] > 0:
        parts.append(f"{counts['warning']} warning")
    if counts["info"] > 0:
        parts.append(f"{counts['info']} info")
    if not parts:
        return "No CORS issues found"
    return f"Found {', '.join(parts)} issue(s)"


# ---------------------------------------------------------------------------
# Live endpoint testing
# ---------------------------------------------------------------------------

def test_endpoint(url: str, origin: str) -> EndpointResult:
    """Test a live endpoint for CORS configuration issues."""
    result = EndpointResult(url=url, origin=origin)

    # 1. Send preflight (OPTIONS) request
    try:
        req = urllib.request.Request(url, method="OPTIONS")
        req.add_header("Origin", origin)
        req.add_header("Access-Control-Request-Method", "POST")
        req.add_header("Access-Control-Request-Headers", "Content-Type, Authorization")
        resp = urllib.request.urlopen(req, timeout=10)
        result.preflight_status = resp.status
        result.preflight_headers = {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as e:
        result.preflight_status = e.code
        result.preflight_headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check="preflight_reachable",
            message="Preflight request failed",
            details=str(e),
        ))
        # Still try the actual request
        result.preflight_status = 0

    # 2. Send actual GET request with Origin
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Origin", origin)
        resp = urllib.request.urlopen(req, timeout=10)
        result.request_status = resp.status
        result.headers = {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as e:
        result.request_status = e.code
        result.headers = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check="request_reachable",
            message="GET request failed",
            details=str(e),
        ))
        return result

    # 3. Analyze headers
    _analyze_headers(result, result.headers, "response")
    if result.preflight_headers:
        _analyze_headers(result, result.preflight_headers, "preflight")
        _analyze_preflight(result)

    # 4. Check for duplicate headers (the #1 CORS bug)
    _check_duplicate_headers(result, url, origin)

    return result


def _analyze_headers(result: EndpointResult, headers: dict, context: str):
    """Analyze CORS headers for common issues."""
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")

    # No CORS header at all
    if not acao:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check=f"{context}_origin_missing",
            message=f"No Access-Control-Allow-Origin in {context}",
            details=f"Origin '{result.origin}' is not allowed or CORS is not configured",
        ))
        return

    # Wildcard with credentials
    if acao == "*" and acac and acac.lower() == "true":
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check=f"{context}_wildcard_credentials",
            message=f"Wildcard origin with credentials in {context}",
            details="Access-Control-Allow-Origin: * cannot be used with "
                    "Access-Control-Allow-Credentials: true. Browsers will reject this.",
        ))

    # Wildcard in production
    if acao == "*":
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check=f"{context}_wildcard_origin",
            message=f"Wildcard origin in {context}",
            details="Access-Control-Allow-Origin: * allows any website to read responses. "
                    "Consider using specific origins in production.",
        ))

    # Origin doesn't match request
    if acao != "*" and acao != result.origin:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check=f"{context}_origin_mismatch",
            message=f"Origin mismatch in {context}",
            details=f"Requested origin: {result.origin}, "
                    f"Returned origin: {acao}",
        ))


def _analyze_preflight(result: EndpointResult):
    """Analyze preflight-specific issues."""
    # Preflight should return 2xx (typically 204)
    if result.preflight_status and result.preflight_status >= 300:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check="preflight_status",
            message=f"Preflight returned {result.preflight_status}",
            details="OPTIONS request should return 204 (No Content). "
                    f"Got {result.preflight_status} instead.",
        ))

    # Check Max-Age
    max_age = result.preflight_headers.get("access-control-max-age")
    if not max_age:
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check="preflight_max_age",
            message="No Access-Control-Max-Age in preflight response",
            details="Without Max-Age, browsers send a preflight for every request. "
                    "Recommended: 86400 (24 hours).",
        ))

    # Check Allow-Methods
    methods = result.preflight_headers.get("access-control-allow-methods")
    if not methods:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check="preflight_methods_missing",
            message="No Access-Control-Allow-Methods in preflight response",
            details="The browser needs to know which HTTP methods are allowed.",
        ))

    # Check Allow-Headers
    allow_headers = result.preflight_headers.get("access-control-allow-headers")
    if not allow_headers:
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check="preflight_headers_missing",
            message="No Access-Control-Allow-Headers in preflight response",
            details="If the request includes custom headers (e.g., Authorization, Content-Type), "
                    "they must be listed in Access-Control-Allow-Headers.",
        ))


def _check_duplicate_headers(result: EndpointResult, url: str, origin: str):
    """Check for duplicate Access-Control-Allow-Origin headers (the #1 CORS bug).

    urllib merges duplicate headers, so we use a raw HTTP request to detect them.
    """
    import http.client
    from urllib.parse import urlparse

    parsed = urlparse(url)
    try:
        if parsed.scheme == "https":
            import ssl
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                                timeout=10, context=ctx)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80,
                                               timeout=10)

        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        conn.request("GET", path, headers={"Origin": origin})
        resp = conn.getresponse()

        # Count Access-Control-Allow-Origin occurrences
        acao_values = []
        for header_name, header_value in resp.getheaders():
            if header_name.lower() == "access-control-allow-origin":
                acao_values.append(header_value)

        if len(acao_values) > 1:
            result.findings.append(Finding(
                severity=Severity.CRITICAL,
                check="duplicate_origin_header",
                message="Duplicate Access-Control-Allow-Origin headers detected",
                details=f"Found {len(acao_values)} values: {acao_values}. "
                        "This is usually caused by both gateway and backend setting CORS headers. "
                        "Browsers reject responses with multiple origin values.",
            ))
        elif len(acao_values) == 1:
            result.findings.append(Finding(
                severity=Severity.INFO,
                check="single_origin_header",
                message="Single Access-Control-Allow-Origin header (correct)",
                details=f"Value: {acao_values[0]}",
            ))

        conn.close()
    except Exception as e:
        result.findings.append(Finding(
            severity=Severity.INFO,
            check="duplicate_check_failed",
            message="Could not perform raw duplicate header check",
            details=str(e),
        ))


# ---------------------------------------------------------------------------
# Static config validation
# ---------------------------------------------------------------------------

def validate_config(filepath: str) -> ConfigResult:
    """Validate a static configuration file for CORS issues."""
    path = Path(filepath)
    content = path.read_text(encoding="utf-8")
    filename = path.name.lower()

    if "caddyfile" in filename or filename.endswith(".caddy"):
        return _validate_caddyfile(filepath, content)
    elif "nginx" in filename or filename.endswith(".conf"):
        return _validate_nginx(filepath, content)
    elif filename.endswith(".json"):
        return _validate_json_policy(filepath, content)
    else:
        # Try to auto-detect
        if "reverse_proxy" in content or "handle" in content:
            return _validate_caddyfile(filepath, content)
        elif "proxy_pass" in content or "server {" in content:
            return _validate_nginx(filepath, content)
        else:
            return ConfigResult(
                file=filepath,
                config_type="unknown",
                findings=[Finding(
                    severity=Severity.WARNING,
                    check="unknown_config_type",
                    message="Could not determine config file type",
                    details="Supported: Caddyfile, nginx.conf, JSON policy",
                )],
            )


def _validate_caddyfile(filepath: str, content: str) -> ConfigResult:
    """Validate Caddy configuration for CORS issues."""
    result = ConfigResult(file=filepath, config_type="caddyfile")

    # Check for CORS headers
    acao_matches = re.findall(
        r'header\s+(?:Access-Control-Allow-Origin)\s+"([^"]*)"', content
    )
    acac_matches = re.findall(
        r'header\s+(?:Access-Control-Allow-Credentials)\s+"([^"]*)"', content
    )

    if not acao_matches:
        result.findings.append(Finding(
            severity=Severity.INFO,
            check="caddy_no_cors",
            message="No CORS headers found in Caddyfile",
            details="CORS may be handled by the backend instead.",
        ))
        return result

    # Check wildcard + credentials
    has_wildcard = "*" in acao_matches
    has_credentials = any(v.lower() == "true" for v in acac_matches)

    if has_wildcard and has_credentials:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check="caddy_wildcard_credentials",
            message="Wildcard origin with credentials in Caddyfile",
            details='Access-Control-Allow-Origin: "*" with '
                    'Access-Control-Allow-Credentials: "true" is rejected by browsers.',
        ))

    if has_wildcard:
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check="caddy_wildcard_origin",
            message="Wildcard origin in Caddyfile",
            details="Consider using a specific origin in production.",
        ))

    # Check for OPTIONS handling
    if "method OPTIONS" not in content and "@cors_preflight" not in content:
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check="caddy_no_preflight",
            message="No OPTIONS/preflight handler found",
            details="Preflight requests may not be handled correctly.",
        ))

    # Check for header_down stripping (indicates dual-layer CORS)
    if "header_down -Access-Control" in content:
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check="caddy_header_stripping",
            message="Upstream CORS header stripping detected",
            details="header_down -Access-Control-* indicates the backend also sets CORS headers. "
                    "Consider disabling CORS in the backend instead (ENABLE_CORS=false).",
        ))

    # Check reverse_proxy targets have consistent CORS handling
    proxy_blocks = re.findall(r'reverse_proxy\s+(\S+)', content)
    if len(proxy_blocks) > 1:
        result.findings.append(Finding(
            severity=Severity.INFO,
            check="caddy_multiple_backends",
            message=f"Multiple reverse_proxy targets: {proxy_blocks}",
            details="Verify that CORS is handled consistently for all backends. "
                    "If Caddy handles CORS globally, all backends should have CORS disabled.",
        ))

    # Unique origins
    unique_origins = set(acao_matches)
    for origin in unique_origins:
        result.findings.append(Finding(
            severity=Severity.INFO,
            check="caddy_origin_value",
            message=f"Allowed origin: {origin}",
            details="",
        ))

    return result


def _validate_nginx(filepath: str, content: str) -> ConfigResult:
    """Validate Nginx configuration for CORS issues."""
    result = ConfigResult(file=filepath, config_type="nginx")

    # Check for CORS headers
    acao_matches = re.findall(
        r"add_header\s+['\"]?Access-Control-Allow-Origin['\"]?\s+['\"]?([^'\";\s]+)", content
    )

    if not acao_matches:
        result.findings.append(Finding(
            severity=Severity.INFO,
            check="nginx_no_cors",
            message="No CORS headers found in nginx config",
            details="CORS may be handled by the backend instead.",
        ))
        return result

    # Check for duplicate add_header in multiple locations
    location_blocks = re.findall(r'location\s+[^\{]+\{[^}]*add_header\s+.*Access-Control[^}]*\}',
                                  content, re.DOTALL)
    global_cors = re.findall(
        r'^(?!\s*location)\s*add_header\s+.*Access-Control', content, re.MULTILINE
    )

    if location_blocks and global_cors:
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check="nginx_cors_scope",
            message="CORS headers set at both server and location level",
            details="In Nginx, add_header in a location block does NOT inherit from server block. "
                    "This can cause inconsistent CORS behavior.",
        ))

    # Check proxy_hide_header (indicates dual-layer)
    if "proxy_hide_header" in content and "Access-Control" in content:
        hide_matches = re.findall(r'proxy_hide_header\s+Access-Control[^;]*', content)
        if hide_matches:
            result.findings.append(Finding(
                severity=Severity.WARNING,
                check="nginx_header_stripping",
                message="Upstream CORS header stripping detected",
                details=f"Found: {hide_matches}. Backend also sets CORS headers. "
                        "Consider disabling CORS in the backend instead.",
            ))

    # Wildcard checks
    has_wildcard = "*" in acao_matches
    acac_matches = re.findall(
        r"add_header\s+['\"]?Access-Control-Allow-Credentials['\"]?\s+['\"]?([^'\";\s]+)", content
    )
    has_credentials = any(v.lower() == "true" for v in acac_matches)

    if has_wildcard and has_credentials:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check="nginx_wildcard_credentials",
            message="Wildcard origin with credentials in nginx config",
            details="Browsers reject * origin with credentials: true.",
        ))

    if has_wildcard:
        result.findings.append(Finding(
            severity=Severity.WARNING,
            check="nginx_wildcard_origin",
            message="Wildcard origin in nginx config",
            details="Consider using specific origins or dynamic origin reflection.",
        ))

    return result


def _validate_json_policy(filepath: str, content: str) -> ConfigResult:
    """Validate a JSON CORS policy file."""
    result = ConfigResult(file=filepath, config_type="json")

    try:
        policy = json.loads(content)
    except json.JSONDecodeError as e:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            check="json_parse_error",
            message="Invalid JSON",
            details=str(e),
        ))
        return result

    # Normalize to list
    policies = policy if isinstance(policy, list) else [policy]

    for i, p in enumerate(policies):
        prefix = f"policy[{i}]" if len(policies) > 1 else "policy"
        origins = p.get("origins", p.get("allowedOrigins", p.get("allow_origins", [])))
        credentials = p.get("credentials", p.get("allowCredentials",
                            p.get("allow_credentials", False)))
        methods = p.get("methods", p.get("allowedMethods", p.get("allow_methods", [])))
        headers = p.get("headers", p.get("allowedHeaders", p.get("allow_headers", [])))
        max_age = p.get("maxAge", p.get("max_age", None))

        # Origin checks
        if isinstance(origins, str):
            origins = [origins]

        if "*" in origins and credentials:
            result.findings.append(Finding(
                severity=Severity.CRITICAL,
                check=f"{prefix}_wildcard_credentials",
                message="Wildcard origin with credentials",
                details="Cannot use * with credentials: true.",
            ))
        elif "*" in origins:
            result.findings.append(Finding(
                severity=Severity.WARNING,
                check=f"{prefix}_wildcard",
                message="Wildcard origin",
                details="Consider specific origins for production.",
            ))

        if not origins:
            result.findings.append(Finding(
                severity=Severity.WARNING,
                check=f"{prefix}_no_origins",
                message="No origins specified",
                details="CORS policy has no allowed origins.",
            ))

        # Method checks
        if isinstance(methods, str):
            methods = [methods]
        if "*" in methods:
            result.findings.append(Finding(
                severity=Severity.WARNING,
                check=f"{prefix}_wildcard_methods",
                message="Wildcard methods",
                details="Consider listing specific HTTP methods.",
            ))

        # Header checks
        if isinstance(headers, str):
            headers = [headers]
        sensitive_exposed = {"set-cookie", "cookie", "authorization"}
        exposed = p.get("exposedHeaders", p.get("expose_headers", []))
        if isinstance(exposed, str):
            exposed = [exposed]
        exposed_lower = {h.lower() for h in exposed}
        sensitive_found = sensitive_exposed & exposed_lower
        if sensitive_found:
            result.findings.append(Finding(
                severity=Severity.WARNING,
                check=f"{prefix}_sensitive_exposed",
                message=f"Sensitive headers exposed: {sensitive_found}",
                details="Exposing sensitive headers increases attack surface.",
            ))

        # Max-age checks
        if max_age is not None:
            if isinstance(max_age, (int, float)):
                if max_age < 0:
                    result.findings.append(Finding(
                        severity=Severity.WARNING,
                        check=f"{prefix}_negative_max_age",
                        message=f"Negative max-age: {max_age}",
                        details="Max-Age should be a positive integer.",
                    ))
                elif max_age > 86400:
                    result.findings.append(Finding(
                        severity=Severity.INFO,
                        check=f"{prefix}_high_max_age",
                        message=f"High max-age: {max_age}s ({max_age/3600:.1f}h)",
                        details="Common value is 86400 (24h). Higher values reduce "
                                "preflight requests but delay config change propagation.",
                    ))

    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_text_report(results: list) -> str:
    """Format findings into a human-readable text report."""
    lines = []
    lines.append("=" * 70)
    lines.append("CORS Audit Report")
    lines.append("=" * 70)

    total = {"critical": 0, "warning": 0, "info": 0}

    for r in results:
        lines.append("")
        if isinstance(r, EndpointResult):
            lines.append(f"Endpoint: {r.url}")
            lines.append(f"Origin:   {r.origin}")
            if r.preflight_status:
                lines.append(f"Preflight status: {r.preflight_status}")
            if r.request_status:
                lines.append(f"Request status:   {r.request_status}")
        elif isinstance(r, ConfigResult):
            lines.append(f"Config: {r.file} ({r.config_type})")

        lines.append("-" * 50)

        if not r.findings:
            lines.append("  No issues found.")
            continue

        for f in r.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            total[sev] = total.get(sev, 0) + 1
            icon = {"critical": "!!!", "warning": " ! ", "info": " i "}
            lines.append(f"  [{icon.get(sev, '   ')}] [{sev.upper()}] {f.message}")
            if f.details:
                for detail_line in f.details.split("\n"):
                    lines.append(f"        {detail_line}")

    lines.append("")
    lines.append("=" * 70)
    lines.append(f"Summary: {total['critical']} critical, "
                 f"{total['warning']} warning, {total['info']} info")

    if total["critical"] > 0:
        lines.append("STATUS: FAIL -- critical issues must be resolved")
    elif total["warning"] > 0:
        lines.append("STATUS: WARN -- review warnings before deploying")
    else:
        lines.append("STATUS: PASS")

    lines.append("=" * 70)

    return "\n".join(lines)


def format_json_report(results: list, fmt: str = "detailed", limit: Optional[int] = None) -> str:
    """Format findings as JSON.

    fmt: "detailed" returns full findings, "concise" returns only summary counts.
    limit: if set, cap the number of findings returned (detailed mode only).
    """
    all_findings = []
    result_data = []

    for r in results:
        d = asdict(r)
        # Convert Severity enums to strings
        for f in d.get("findings", []):
            if hasattr(f["severity"], "value"):
                f["severity"] = f["severity"].value
        all_findings.extend(d.get("findings", []))
        result_data.append(d)

    counts = {"critical": 0, "warning": 0, "info": 0}
    for f in all_findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    hint = _make_hint(counts)

    if fmt == "concise":
        output = {
            "summary": counts,
            "total_findings": len(all_findings),
            "hint": hint,
        }
    else:
        # Apply limit to findings within each result
        if limit is not None and limit > 0:
            remaining = limit
            for d in result_data:
                d["findings"] = d["findings"][:remaining]
                remaining -= len(d["findings"])
                if remaining <= 0:
                    break

        output = {
            "results": result_data,
            "summary": counts,
            "total_findings": len(all_findings),
            "hint": hint,
        }
        if limit is not None:
            output["limit_applied"] = limit

    return json.dumps(output, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_preflight():
    """Check that the script can run: Python version, stdlib availability."""
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ok = sys.version_info >= (3, 7)

    result = {
        "ready": ok,
        "dependencies": {
            "python3": {
                "status": "ok" if ok else "error",
                "version": python_version,
                "minimum": "3.7",
            }
        },
        "credentials": {},
        "services": {},
        "hint": f"CORS validator ready (Python {python_version})" if ok
                else f"Python >= 3.7 required, found {python_version}",
    }
    print(json.dumps(result, indent=2))
    sys.exit(0 if ok else 2)


def cmd_validate(args):
    """Run CORS validation on endpoints or config files."""
    results = []

    if args.url:
        if not args.origin:
            emit_error(
                error="--origin is required when using --url",
                hint="Add --origin https://your-frontend.com",
                recoverable=True,
                exit_code=1,
            )
        results.append(test_endpoint(args.url, args.origin))

    elif args.url_file:
        if not args.origin:
            emit_error(
                error="--origin is required when using --url-file",
                hint="Add --origin https://your-frontend.com",
                recoverable=True,
                exit_code=1,
            )
        url_file_path = Path(args.url_file)
        if not url_file_path.exists():
            emit_error(
                error=f"URL file not found: {args.url_file}",
                hint="Check the file path and try again",
                recoverable=True,
                exit_code=1,
            )
        urls = url_file_path.read_text().strip().splitlines()
        for url in urls:
            url = url.strip()
            if url and not url.startswith("#"):
                results.append(test_endpoint(url, args.origin))

    elif args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            emit_error(
                error=f"Config file not found: {args.config}",
                hint="Check the file path and try again",
                recoverable=True,
                exit_code=1,
            )
        results.append(validate_config(args.config))

    else:
        emit_error(
            error="No input specified",
            hint="Use --url, --url-file, or --config to specify what to validate",
            recoverable=True,
            exit_code=1,
        )

    # Format output
    fmt = args.format
    if fmt == "text":
        report = format_text_report(results)
    else:
        # "json" (detailed) or "concise"
        json_fmt = "concise" if fmt == "concise" else "detailed"
        report = format_json_report(results, fmt=json_fmt, limit=args.limit)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        # Even when writing to file, produce JSON on stdout
        print(json.dumps({
            "hint": f"Report written to {args.output}",
        }))
    else:
        print(report)

    # Exit 0 always on successful audit completion.
    # Audit finding severity does NOT affect exit code.
    sys.exit(0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CORS configuration validator for live endpoints and static configs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command")

    # preflight subcommand
    subparsers.add_parser("preflight", help="Check runtime dependencies")

    # validate subcommand
    validate_parser = subparsers.add_parser("validate", help="Run CORS validation")

    group = validate_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Live endpoint URL to test")
    group.add_argument("--url-file", help="File with URLs to test (one per line)")
    group.add_argument("--config", help="Static config file to validate (Caddyfile, nginx.conf, JSON)")

    validate_parser.add_argument("--origin", help="Origin header to send (required for --url/--url-file)")
    validate_parser.add_argument("--output", help="Output file path (default: stdout)")
    validate_parser.add_argument("--format", choices=["json", "text", "concise"], default="json",
                                 help="Output format: json (detailed, default), concise (summary only), text (human-readable)")
    validate_parser.add_argument("--limit", type=int, default=None,
                                 help="Max number of findings to include in JSON output")

    args = parser.parse_args()

    if args.command == "preflight":
        cmd_preflight()
    elif args.command == "validate":
        cmd_validate(args)
    else:
        emit_error(
            error=f"Unknown or missing subcommand: {args.command or '(none)'}",
            hint="Valid subcommands: preflight, validate",
            recoverable=True,
            exit_code=1,
        )


if __name__ == "__main__":
    main()
