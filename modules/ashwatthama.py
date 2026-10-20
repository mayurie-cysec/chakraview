"""
ASHWATTHAMA — the warrior who would not let the past rest.

The Wayback Machine remembers URLs that were deleted years ago, and the
endpoint behind one of those URLs is very often still live. This pulls the
full CDX index for the domain, then sorts what it finds into the categories
that are actually worth chasing: sensitive file extensions, admin paths,
parameters that suggest injection or file access, and API routes.

Parameter extraction matters more than the path list. A URL with ?file= or
?redirect= in it is a test case, and the archive hands over thousands of them
for free.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

from core.context import Context
from core.models import Severity
from core.net import apex_domain
from modules import shuddhi

# Extensions that should not be reachable on a web server.
SENSITIVE_EXTENSIONS = {
    ".sql": Severity.HIGH, ".env": Severity.HIGH, ".bak": Severity.HIGH,
    ".backup": Severity.HIGH, ".old": Severity.MEDIUM, ".orig": Severity.MEDIUM,
    ".save": Severity.MEDIUM, ".swp": Severity.MEDIUM, ".key": Severity.HIGH,
    ".pem": Severity.HIGH, ".pfx": Severity.HIGH, ".p12": Severity.HIGH,
    ".jks": Severity.HIGH, ".keystore": Severity.HIGH, ".log": Severity.MEDIUM,
    ".config": Severity.MEDIUM, ".conf": Severity.MEDIUM, ".ini": Severity.MEDIUM,
    ".yml": Severity.LOW, ".yaml": Severity.LOW, ".zip": Severity.MEDIUM,
    ".tar": Severity.MEDIUM, ".gz": Severity.MEDIUM, ".tgz": Severity.MEDIUM,
    ".rar": Severity.MEDIUM, ".7z": Severity.MEDIUM, ".dump": Severity.HIGH,
    ".sqlite": Severity.HIGH, ".db": Severity.HIGH, ".mdb": Severity.HIGH,
    ".csv": Severity.LOW, ".xls": Severity.LOW, ".xlsx": Severity.LOW,
    ".pdf": Severity.INFO, ".doc": Severity.INFO, ".docx": Severity.INFO,
    ".git": Severity.HIGH, ".tfstate": Severity.HIGH, ".kdbx": Severity.HIGH,
}

ADMIN_PATH_TOKENS = [
    "admin", "administrator", "wp-admin", "phpmyadmin", "adminer",
    "dashboard", "console", "manage", "management", "backoffice",
    "cpanel", "webadmin", "sysadmin", "controlpanel", "_admin",
]

API_PATH_TOKENS = [
    "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/rpc/",
    "/soap/", "/internal/", "/private/", "/service/", "/ws/",
]

# Parameters that map to a well-known vulnerability class. These are the
# fastest route from an archive dump to a working test case.
INTERESTING_PARAMS: dict[str, tuple[str, Severity]] = {
    "url": ("SSRF / open redirect", Severity.MEDIUM),
    "uri": ("SSRF / open redirect", Severity.MEDIUM),
    "redirect": ("open redirect", Severity.MEDIUM),
    "redirect_uri": ("open redirect / OAuth", Severity.MEDIUM),
    "redirect_url": ("open redirect", Severity.MEDIUM),
    "next": ("open redirect", Severity.LOW),
    "return": ("open redirect", Severity.LOW),
    "returnurl": ("open redirect", Severity.LOW),
    "continue": ("open redirect", Severity.LOW),
    "dest": ("open redirect", Severity.LOW),
    "destination": ("open redirect", Severity.LOW),
    "callback": ("JSONP / open redirect", Severity.LOW),
    "file": ("path traversal / LFI", Severity.MEDIUM),
    "filename": ("path traversal / LFI", Severity.MEDIUM),
    "path": ("path traversal", Severity.MEDIUM),
    "doc": ("path traversal", Severity.LOW),
    "document": ("path traversal", Severity.LOW),
    "folder": ("path traversal", Severity.LOW),
    "download": ("path traversal", Severity.MEDIUM),
    "template": ("template injection / LFI", Severity.MEDIUM),
    "page": ("LFI / SQL injection", Severity.LOW),
    "include": ("file inclusion", Severity.MEDIUM),
    "id": ("IDOR / SQL injection", Severity.LOW),
    "user_id": ("IDOR", Severity.MEDIUM),
    "userid": ("IDOR", Severity.MEDIUM),
    "account": ("IDOR", Severity.MEDIUM),
    "order": ("IDOR", Severity.LOW),
    "invoice": ("IDOR", Severity.MEDIUM),
    "q": ("XSS / SQL injection", Severity.LOW),
    "query": ("XSS / SQL injection", Severity.LOW),
    "search": ("XSS", Severity.LOW),
    "s": ("XSS", Severity.LOW),
    "cmd": ("command injection", Severity.HIGH),
    "exec": ("command injection", Severity.HIGH),
    "command": ("command injection", Severity.HIGH),
    "ping": ("command injection", Severity.MEDIUM),
    "host": ("SSRF", Severity.MEDIUM),
    "ip": ("SSRF", Severity.MEDIUM),
    "port": ("SSRF", Severity.LOW),
    "data": ("deserialisation", Severity.LOW),
    "xml": ("XXE", Severity.MEDIUM),
    "token": ("token in URL — logged and referred", Severity.MEDIUM),
    "key": ("key in URL — logged and referred", Severity.MEDIUM),
    "api_key": ("key in URL — logged and referred", Severity.HIGH),
    "apikey": ("key in URL — logged and referred", Severity.HIGH),
    "password": ("credential in URL", Severity.HIGH),
    "passwd": ("credential in URL", Severity.HIGH),
    "pwd": ("credential in URL", Severity.HIGH),
    "secret": ("secret in URL", Severity.HIGH),
    "access_token": ("token in URL", Severity.HIGH),
    "session": ("session identifier in URL", Severity.MEDIUM),
    "sessionid": ("session identifier in URL", Severity.MEDIUM),
    "debug": ("debug mode toggle", Severity.MEDIUM),
    "test": ("debug/test toggle", Severity.LOW),
    "admin": ("privilege toggle", Severity.MEDIUM),
}


async def _fetch_cdx(ctx: Context, domain: str) -> list[str]:
    """Pull the archive index. Retries, because the CDX API is often degraded."""
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=50000"
    )
    for attempt in range(2):
        text = await ctx.http.text(url, timeout=50.0)
        if text:
            return [line.strip() for line in text.splitlines() if line.strip()]
        await asyncio.sleep(1.5)
    return []


async def run(ctx: Context) -> None:
    res = ctx.result
    key = "archive"
    apex = apex_domain(ctx.target)

    ctx.progress.task(key, "Fetching Wayback CDX index")
    urls = await _fetch_cdx(ctx, apex)

    if not urls:
        res.archive = {"found": False, "note": "Archive unreachable or empty", "total": 0}
        ctx.progress.note(key, "no archive data (service unreachable or nothing indexed)")
        return

    ctx.progress.note(key, f"{len(urls)} archived URLs retrieved")
    ctx.progress.task(key, "Classifying archived URLs", total=len(urls))

    sensitive: list[tuple[str, Severity, str]] = []
    admin_paths: set[str] = set()
    api_paths: set[str] = set()
    params: dict[str, set[str]] = {}
    extensions: Counter[str] = Counter()
    hosts_seen: set[str] = set()

    for index, raw in enumerate(urls):
        if index % 2000 == 0:
            ctx.progress.advance(key, 2000)
        clean = shuddhi.sanitize(raw, max_len=600)
        parsed = urlparse(clean if "//" in clean else f"http://{clean}")
        path = parsed.path or "/"
        lower_path = path.lower()

        if parsed.hostname:
            host = shuddhi.normalise_host(parsed.hostname)
            if host:
                hosts_seen.add(host)
                res.add_subdomain(host, "wayback")

        # Extension classification
        if "." in lower_path.rsplit("/", 1)[-1]:
            ext = "." + lower_path.rsplit(".", 1)[-1][:12]
            extensions[ext] += 1
            if ext in SENSITIVE_EXTENSIONS:
                sensitive.append((clean, SENSITIVE_EXTENSIONS[ext], ext))

        if any(token in lower_path for token in ADMIN_PATH_TOKENS):
            admin_paths.add(clean)
        if any(token in lower_path for token in API_PATH_TOKENS):
            api_paths.add(clean)

        if parsed.query:
            for name in parse_qs(parsed.query, keep_blank_values=True):
                clean_name = shuddhi.sanitize(name, max_len=60).lower()
                if clean_name:
                    params.setdefault(clean_name, set()).add(clean)

    ctx.progress.advance(key, len(urls) % 2000)

    # Highest-severity sensitive hits first, deduplicated.
    sensitive.sort(key=lambda item: -int(item[1]))
    seen_urls: set[str] = set()
    unique_sensitive = []
    for url, severity, ext in sensitive:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        unique_sensitive.append({"url": url, "severity": severity.label, "ext": ext})

    interesting_params = {
        name: {"reason": INTERESTING_PARAMS[name][0],
               "severity": INTERESTING_PARAMS[name][1].label,
               "count": len(urls_for),
               "sample": sorted(urls_for)[0]}
        for name, urls_for in params.items() if name in INTERESTING_PARAMS
    }

    res.archive = {
        "found": True,
        "total": len(urls),
        "hosts": sorted(hosts_seen),
        "sensitive": unique_sensitive[:200],
        "admin_paths": sorted(admin_paths)[:100],
        "api_paths": sorted(api_paths)[:150],
        "parameters": {k: sorted(v)[:3] for k, v in sorted(params.items())[:400]},
        "interesting_parameters": interesting_params,
        "extensions": dict(extensions.most_common(25)),
        "note": f"{len(urls)} archived URLs, {len(unique_sensitive)} sensitive, "
                f"{len(params)} distinct parameters",
    }

    # ── Findings ──────────────────────────────────────────────────────────
    by_severity: dict[str, list[dict]] = {}
    for item in unique_sensitive:
        by_severity.setdefault(item["severity"], []).append(item)

    for severity_label in ("HIGH", "MEDIUM"):
        items = by_severity.get(severity_label, [])
        if not items:
            continue
        exts = sorted({item["ext"] for item in items})
        res.report(
            severity_label,
            f"{len(items)} archived URLs point at sensitive file types",
            asset=apex,
            detail="The Wayback Machine indexed URLs with extensions that "
                   f"should never be web-reachable ({', '.join(exts)}). Each is "
                   "worth requesting directly — these files are frequently "
                   "still present on the live server even after the linking "
                   "page was removed.",
            evidence="; ".join(item["url"] for item in items[:8]),
            chakra="ASHWATTHAMA",
            remediation="Remove the files from the document root and block the "
                        "extensions at the web server.",
        )

    credential_params = {
        name: info for name, info in interesting_params.items()
        if info["severity"] in ("HIGH", "CRITICAL")
    }
    if credential_params:
        res.report(
            Severity.HIGH,
            f"{len(credential_params)} archived URLs carry credentials in the query string",
            asset=apex,
            detail="Parameters such as "
                   + ", ".join(sorted(credential_params)[:8])
                   + " appear in archived URLs. Values in a query string end up "
                   "in server logs, proxy logs, browser history and the Referer "
                   "header sent to third parties, so any credential passed this "
                   "way should be treated as disclosed.",
            evidence="; ".join(info["sample"] for info in list(credential_params.values())[:5]),
            chakra="ASHWATTHAMA",
            remediation="Move these values into headers or a POST body and "
                        "rotate anything that was ever sent in a URL.",
        )

    if interesting_params:
        res.report(
            Severity.INFO,
            f"{len(interesting_params)} archived parameters map to known vulnerability classes",
            asset=apex,
            detail="Recovered parameter names and the class each one suggests: "
                   + "; ".join(
                       f"{name} → {info['reason']}"
                       for name, info in sorted(interesting_params.items())[:20]
                   )
                   + ". These are ready-made test cases against the live "
                     "application.",
            evidence=f"{len(params)} distinct parameters recovered in total",
            chakra="ASHWATTHAMA",
        )

    if admin_paths:
        res.report(
            Severity.LOW,
            f"{len(admin_paths)} archived administrative paths",
            asset=apex,
            detail="Archived URLs reference administrative interfaces. Even "
                   "where the path now returns 404, it indicates what software "
                   "was deployed and where its console used to live.",
            evidence="; ".join(sorted(admin_paths)[:8]),
            chakra="ASHWATTHAMA",
        )

    new_hosts = len(hosts_seen)
    ctx.progress.chakra_done(
        key,
        f"{len(urls)} URLs · {len(unique_sensitive)} sensitive · "
        f"{len(interesting_params)} notable params · {new_hosts} hosts",
    )
