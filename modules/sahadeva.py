"""
SAHADEVA — the brother who knew what others could not see.

Front-end JavaScript is the most under-tested part of most web applications.
It is shipped to every visitor, and it routinely contains the full list of API
routes the application can reach, plus credentials that were never supposed to
leave the server.

Scope rule: only first-party scripts are scanned. A secret in a third-party
CDN bundle belongs to that vendor and reporting it as the client's finding is
noise, so scripts are filtered to the target's own apex before any matching.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from core.context import Context
from core.models import Severity, Subdomain
from core.net import apex_domain
from modules import shuddhi

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
_INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>", re.I | re.S)

# (label, severity, pattern). Patterns are deliberately specific — a generic
# "looks like a token" rule produces findings nobody can act on.
SECRET_PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("AWS access key ID", Severity.CRITICAL,
     re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b")),
    ("Private key block", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY")),
    ("GitHub token", Severity.CRITICAL,
     re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("GitLab personal access token", Severity.CRITICAL,
     re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20})\b")),
    ("Slack token", Severity.CRITICAL,
     re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,48})\b")),
    ("Slack webhook", Severity.HIGH,
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)")),
    ("Stripe live secret key", Severity.CRITICAL,
     re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b")),
    ("SendGrid API key", Severity.CRITICAL,
     re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")),
    ("Mailgun API key", Severity.HIGH,
     re.compile(r"\b(key-[0-9a-zA-Z]{32})\b")),
    ("Twilio account SID", Severity.HIGH,
     re.compile(r"\b(AC[0-9a-fA-F]{32})\b")),
    ("npm access token", Severity.CRITICAL,
     re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("OpenAI API key", Severity.CRITICAL,
     re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b")),
    ("Anthropic API key", Severity.CRITICAL,
     re.compile(r"\b(sk-ant-api\d{2}-[A-Za-z0-9_\-]{50,})\b")),
    ("Square access token", Severity.CRITICAL,
     re.compile(r"\b(sq0atp-[A-Za-z0-9_\-]{22})\b")),
    ("Braintree production token", Severity.CRITICAL,
     re.compile(r"(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})")),
    ("Google API key", Severity.HIGH,
     re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("Google OAuth client secret", Severity.HIGH,
     re.compile(r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b")),
    ("Firebase database URL", Severity.MEDIUM,
     re.compile(r"(https://[a-z0-9\-]+\.firebaseio\.com)")),
    ("JSON Web Token", Severity.MEDIUM,
     re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b")),
    ("Basic auth credentials in URL", Severity.HIGH,
     re.compile(r"https?://[A-Za-z0-9._%\-]+:([^@/\s\"']{3,})@[A-Za-z0-9.\-]+")),
    ("Hardcoded credential assignment", Severity.MEDIUM,
     re.compile(
         r"""['"]?(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|"""
         r"""auth[_-]?token|access[_-]?token|private[_-]?key|password|passwd)"""
         r"""['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-+/=.]{16,})['"]""",
         re.I,
     )),
]

# Values that match a pattern but mean nothing — placeholders and examples.
_PLACEHOLDER_RE = re.compile(
    r"^(?:x{3,}|0{6,}|1{6,}|a{6,}|your[_-]?|my[_-]?|test|dummy|sample|example|"
    r"placeholder|changeme|insert|todo|fixme|none|null|undefined|false|true|"
    r"process\.env|import\.meta|\$\{|\{\{)",
    re.I,
)

_ENDPOINT_RE = re.compile(
    r"""["'`](/(?:api|v\d|rest|graphql|internal|admin|auth|oauth|user|users|"""
    r"""account|accounts|upload|download|file|files|export|import|report|"""
    r"""reports|search|query|webhook|callback|session|token|login|logout|"""
    r"""register|payment|order|orders|invoice|config|settings|debug|health|"""
    r"""graph|rpc|service|services)[A-Za-z0-9_\-/.{}:$]*)["'`]"""
)

_ABS_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+/[A-Za-z0-9_\-/.?=&%]{2,})["'`]""")


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value.strip()))


def _scan_text(source: str, text: str) -> list[dict]:
    """Match every secret pattern against one script body."""
    hits: list[dict] = []
    for label, severity, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            if _is_placeholder(value):
                continue
            # Keep enough of the value to identify it, not enough to use it.
            redacted = value[:6] + "…" + value[-4:] if len(value) > 14 else value[:4] + "…"
            hits.append({
                "type": label,
                "severity": severity.label,
                "source": source,
                "match": shuddhi.sanitize(redacted, max_len=80),
                "context": shuddhi.sanitize(
                    text[max(0, match.start() - 40):match.end() + 40].replace("\n", " "),
                    max_len=180,
                ),
            })
            break  # one finding per pattern per file is enough to act on
    return hits


def _extract_endpoints(text: str, limit: int = 400) -> set[str]:
    found: set[str] = set()
    for match in _ENDPOINT_RE.finditer(text):
        found.add(shuddhi.sanitize(match.group(1), max_len=200))
        if len(found) >= limit:
            break
    for match in _ABS_URL_RE.finditer(text):
        found.add(shuddhi.sanitize(match.group(1), max_len=200))
        if len(found) >= limit * 2:
            break
    return found


async def run(ctx: Context) -> None:
    res = ctx.result
    key = "js"
    apex = apex_domain(ctx.target)

    alive = [e for e in res.hosts_alive() if e.status and 200 <= e.status < 400]
    if not alive:
        ctx.progress.note(key, "no live hosts with a usable response")
        return

    alive.sort(key=lambda e: (e.status != 200, e.host))
    hosts = alive[: ctx.cfg.max_js_hosts]
    if len(alive) > len(hosts):
        ctx.progress.note(
            key, f"mining {len(hosts)} of {len(alive)} live hosts (--deep raises this)"
        )

    # ── Collect script URLs from each page ────────────────────────────────
    ctx.progress.task(key, f"Collecting scripts from {len(hosts)} pages", total=len(hosts))
    script_urls: set[str] = set()
    inline_bodies: list[tuple[str, str]] = []
    sem = asyncio.Semaphore(ctx.cfg.concurrency)

    async def collect(entry: Subdomain) -> None:
        if ctx.cancelled():
            ctx.progress.advance(key)
            return
        async with sem:
            resp = await ctx.http.get(entry.url or f"https://{entry.host}")
        ctx.progress.advance(key)
        if resp is None:
            return
        try:
            body = resp.text[:600_000]
        except (UnicodeDecodeError, ValueError):
            return

        base = str(resp.url)
        for src in _SCRIPT_SRC_RE.findall(body):
            absolute = urljoin(base, src.strip())
            host = urlparse(absolute).hostname or ""
            # First-party only: a vendor's bundle is not this client's finding.
            if host.endswith(apex):
                script_urls.add(absolute)

        for inline in _INLINE_SCRIPT_RE.findall(body):
            if len(inline.strip()) > 80:
                inline_bodies.append((f"{base} (inline)", inline[:120_000]))

    await asyncio.gather(*(collect(e) for e in hosts))

    max_scripts = 120 if not ctx.cfg.deep else 500
    ordered = sorted(script_urls)[:max_scripts]
    ctx.progress.note(
        key, f"{len(script_urls)} first-party scripts, {len(inline_bodies)} inline blocks"
    )

    # ── Fetch and mine each script ────────────────────────────────────────
    ctx.progress.task(key, f"Mining {len(ordered)} scripts", total=len(ordered) or 1)
    secrets: list[dict] = []
    endpoints: set[str] = set()

    async def mine(url: str) -> None:
        if ctx.cancelled():
            ctx.progress.advance(key)
            return
        async with sem:
            text = await ctx.http.text(url)
        ctx.progress.advance(key)
        if not text:
            return
        text = text[:1_500_000]
        for hit in _scan_text(url, text):
            secrets.append(hit)
            ctx.progress.hit(key, f"{hit['type']} in {url.rsplit('/', 1)[-1][:40]}")
        endpoints.update(_extract_endpoints(text))

    await asyncio.gather(*(mine(u) for u in ordered))

    for source, body in inline_bodies[:60]:
        for hit in _scan_text(source, body):
            secrets.append(hit)
            ctx.progress.hit(key, f"{hit['type']} inline at {source[:50]}")
        endpoints.update(_extract_endpoints(body))

    res.secrets = secrets
    res.endpoints = sorted(endpoints)

    # ── Report ────────────────────────────────────────────────────────────
    # One finding per secret type, listing every file it appeared in.
    by_type: dict[str, list[dict]] = {}
    for hit in secrets:
        by_type.setdefault(hit["type"], []).append(hit)

    for secret_type, hits in by_type.items():
        severity = hits[0]["severity"]
        sources = [h["source"] for h in hits]
        res.report(
            severity,
            f"{secret_type} hardcoded in client-side JavaScript",
            asset=sources[0],
            detail=f"A value matching a {secret_type.lower()} is present in "
                   f"{len(hits)} first-party script(s). Anything shipped to the "
                   "browser is readable by every visitor, so this credential "
                   "should be treated as disclosed and rotated regardless of "
                   "whether it is currently in use.",
            evidence=f"{hits[0]['match']} — {hits[0]['context']}",
            chakra="SAHADEVA",
            remediation="Rotate the credential, move the call server-side, and "
                        "scan the git history — it is almost certainly "
                        "committed as well.",
            references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        )

    if endpoints:
        interesting = [e for e in sorted(endpoints) if any(
            token in e.lower() for token in
            ("admin", "internal", "debug", "config", "token", "secret", "upload", "export")
        )]
        res.report(
            Severity.INFO,
            f"{len(endpoints)} API endpoints recovered from JavaScript",
            asset=ctx.target,
            detail="These routes were extracted from first-party scripts. They "
                   "are the application's real attack surface and are usually "
                   "absent from any documentation — test each for "
                   "authorisation, not just authentication."
                   + (f" {len(interesting)} reference admin, internal, debug or "
                      "export functionality." if interesting else ""),
            evidence=", ".join((interesting or sorted(endpoints))[:20]),
            chakra="SAHADEVA",
        )

    ctx.progress.chakra_done(
        key, f"{len(ordered)} scripts · {len(endpoints)} endpoints · {len(secrets)} secret(s)"
    )
