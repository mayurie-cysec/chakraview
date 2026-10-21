"""
ARJUNA — precision aim on every live host.

Enumeration gives you a list of names. This turns that list into a triage
queue: what answers, on which scheme, with what status, title, server and
technology stack, and which hosts leak something immediately.

Three checks here produce findings on their own rather than just context:
exposed version-control and environment files, a reflected CORS origin with
credentials enabled, and directory listings. All three are common, and all
three are reportable without further work.
"""

from __future__ import annotations

import asyncio
import re

from core.context import Context
from core.models import Severity, Subdomain
from modules import shuddhi

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# Technology fingerprints: (label, header-name-or-empty, pattern).
# An empty header name means the pattern is matched against the response body.
FINGERPRINTS: list[tuple[str, str, str]] = [
    ("WordPress", "", r"wp-content|wp-includes|/wp-json/"),
    ("Drupal", "", r"Drupal\.settings|/sites/default/files"),
    ("Joomla", "", r"/media/jui/|Joomla!"),
    ("Magento", "", r"Mage\.Cookies|/static/version"),
    ("Shopify", "", r"cdn\.shopify\.com"),
    ("Laravel", "set-cookie", r"laravel_session|XSRF-TOKEN"),
    ("Django", "", r"csrfmiddlewaretoken|Django administration"),
    ("Rails", "set-cookie", r"_rails|_session_id"),
    ("Express", "x-powered-by", r"Express"),
    ("ASP.NET", "x-powered-by", r"ASP\.NET"),
    ("ASP.NET", "", r"__VIEWSTATE|__EVENTVALIDATION"),
    ("PHP", "x-powered-by", r"PHP/"),
    ("Next.js", "", r"/_next/static|__NEXT_DATA__"),
    ("Nuxt", "", r"__NUXT__|/_nuxt/"),
    ("React", "", r"data-reactroot|react-dom"),
    ("Angular", "", r"ng-version|angular(\.min)?\.js"),
    ("Vue", "", r"vue(\.runtime)?(\.min)?\.js|data-v-[0-9a-f]{8}"),
    ("jQuery", "", r"jquery[.-][0-9]"),
    ("Bootstrap", "", r"bootstrap(\.min)?\.(css|js)"),
    ("Cloudflare", "server", r"cloudflare"),
    ("nginx", "server", r"nginx"),
    ("Apache", "server", r"Apache"),
    ("IIS", "server", r"Microsoft-IIS"),
    ("LiteSpeed", "server", r"LiteSpeed"),
    ("Tomcat", "", r"Apache Tomcat"),
    ("Jenkins", "x-jenkins", r".+"),
    ("Jenkins", "", r"Jenkins ver\.|jenkins-session"),
    ("GitLab", "", r"gitlab-static|GitLab Community|GitLab Enterprise"),
    ("Grafana", "", r"grafana[-_]?bootdata|Grafana"),
    ("Kibana", "", r"kbn-name|Kibana"),
    ("Jira", "", r"jira\.webresources|Atlassian Jira"),
    ("Confluence", "", r"confluence-context-path|Atlassian Confluence"),
    ("phpMyAdmin", "", r"phpMyAdmin"),
    ("Swagger UI", "", r"swagger-ui|swagger\.json"),
    ("GraphQL", "", r"GraphiQL|__schema"),
    ("Keycloak", "", r"/auth/realms/|keycloak"),
    ("Traefik", "", r"traefik"),
    ("MinIO", "server", r"MinIO"),
    ("Varnish", "via", r"varnish"),
    ("Akamai", "server", r"AkamaiGHost"),
]

# Files that should never be reachable but routinely are.
# (path, severity, title, body_must_contain) — the last field stops a soft
# 404 page from being reported as a real exposure.
QUICK_WINS: list[tuple[str, Severity, str, str]] = [
    ("/.git/HEAD", Severity.CRITICAL, "Exposed .git repository", "ref:"),
    ("/.git/config", Severity.CRITICAL, "Exposed .git configuration", "[core]"),
    ("/.env", Severity.CRITICAL, "Exposed .env file", "="),
    ("/.svn/entries", Severity.HIGH, "Exposed Subversion metadata", ""),
    ("/.htaccess", Severity.MEDIUM, "Readable .htaccess file", ""),
    ("/.DS_Store", Severity.LOW, "Exposed .DS_Store file", ""),
    ("/server-status", Severity.MEDIUM, "Apache mod_status exposed", "Server Status"),
    ("/actuator/env", Severity.CRITICAL, "Spring Boot Actuator env exposed", "propertySources"),
    ("/actuator/health", Severity.LOW, "Spring Boot Actuator reachable", "status"),
    ("/.aws/credentials", Severity.CRITICAL, "Exposed AWS credentials file", "aws_access_key"),
    ("/config.json", Severity.MEDIUM, "Readable config.json", "{"),
    ("/phpinfo.php", Severity.HIGH, "phpinfo() page exposed", "PHP Version"),
    ("/.well-known/security.txt", Severity.INFO, "security.txt published", "ontact"),
    ("/swagger.json", Severity.LOW, "OpenAPI specification exposed", "swagger"),
    ("/graphql", Severity.LOW, "GraphQL endpoint reachable", ""),
    ("/.git-credentials", Severity.CRITICAL, "Exposed git credentials file", "http"),
    ("/wp-config.php.bak", Severity.CRITICAL, "WordPress config backup exposed", "DB_"),
    ("/backup.sql", Severity.CRITICAL, "Database dump exposed", ""),
]

# Security headers whose absence is worth one consolidated finding.
SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS — forces HTTPS on subsequent visits",
    "content-security-policy": "CSP — primary defence against injected script",
    "x-frame-options": "Clickjacking protection (or CSP frame-ancestors)",
    "x-content-type-options": "Stops MIME-type sniffing",
    "referrer-policy": "Controls how much URL data leaks to third parties",
}

DIRECTORY_LISTING_RE = re.compile(
    r"<title>Index of /|Directory listing for|<h1>Index of /", re.I
)


def _extract_title(body: str) -> str:
    match = _TITLE_RE.search(body)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return shuddhi.sanitize(title, max_len=120)


def _fingerprint(headers: dict[str, str], body: str) -> list[str]:
    found: list[str] = []
    lower_body = body[:200_000]
    for label, header, pattern in FINGERPRINTS:
        if label in found:
            continue
        haystack = lower_body if not header else headers.get(header, "")
        if haystack and re.search(pattern, haystack, re.I):
            found.append(label)
    return found


async def _probe_host(ctx: Context, entry: Subdomain) -> None:
    """Try HTTPS then HTTP, and record whatever answers."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{entry.host}"
        resp = await ctx.http.get(url)
        if resp is None:
            continue

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = ""
        try:
            body = resp.text[:300_000]
        except (UnicodeDecodeError, ValueError):
            body = ""

        entry.scheme = scheme
        entry.url = str(resp.url) if resp.url else url
        entry.status = resp.status_code
        entry.title = _extract_title(body)
        entry.server = shuddhi.sanitize(headers.get("server", ""), max_len=80)
        entry.tech = _fingerprint(headers, body)
        entry.redirect = shuddhi.sanitize(headers.get("location", ""), max_len=300)
        try:
            entry.content_length = int(headers.get("content-length", "") or len(body))
        except ValueError:
            entry.content_length = len(body)

        _check_headers(ctx, entry, resp)

        if DIRECTORY_LISTING_RE.search(body):
            ctx.result.report(
                Severity.MEDIUM,
                "Directory listing enabled",
                asset=entry.url,
                detail="The web server renders an index of the directory "
                       "instead of a page, disclosing filenames that were "
                       "never meant to be discoverable.",
                evidence=_extract_title(body) or "Index of /",
                chakra="ARJUNA",
                remediation="Disable automatic directory indexes "
                            "(Options -Indexes, or autoindex off).",
            )
        return


async def _check_cors(ctx: Context, entry: Subdomain) -> None:
    """Reflecting an arbitrary Origin with credentials is a real finding."""
    probe_origin = "https://chakraview-cors-probe.example"
    resp = await ctx.http.get(entry.url, headers={"Origin": probe_origin})
    if resp is None:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    allow_origin = headers.get("access-control-allow-origin", "").strip()
    allow_creds = headers.get("access-control-allow-credentials", "").strip().lower()

    if allow_origin == probe_origin and allow_creds == "true":
        ctx.result.report(
            Severity.HIGH,
            "CORS reflects arbitrary origin with credentials",
            asset=entry.url,
            detail="The server echoes back whatever Origin it is sent and also "
                   "sets Access-Control-Allow-Credentials: true. Any website a "
                   "victim visits can therefore read authenticated responses "
                   "from this host using the victim's session.",
            evidence=f"Origin: {probe_origin} → Access-Control-Allow-Origin: "
                     f"{shuddhi.sanitize(allow_origin, max_len=120)}; "
                     "Access-Control-Allow-Credentials: true",
            chakra="ARJUNA",
            remediation="Validate Origin against an allowlist and never combine "
                        "a reflected origin with credentialed responses.",
            references=["https://portswigger.net/web-security/cors"],
        )
    elif allow_origin == "*" and allow_creds == "true":
        ctx.result.report(
            Severity.MEDIUM,
            "CORS wildcard combined with credentials",
            asset=entry.url,
            detail="Access-Control-Allow-Origin is * while credentials are "
                   "allowed. Browsers reject this combination, so the intended "
                   "sharing is broken and the configuration signals that the "
                   "policy was never tested.",
            evidence="Access-Control-Allow-Origin: * with credentials: true",
            chakra="ARJUNA",
            remediation="Name the permitted origins explicitly.",
        )


def _check_headers(ctx: Context, entry: Subdomain, resp) -> None:
    """One consolidated finding per host for missing security headers.

    Takes the response the probe already made rather than issuing its own —
    re-requesting every live host just to re-read its headers doubled the
    traffic the scan generated for nothing.
    """
    if resp.status_code >= 500:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = [name for name in SECURITY_HEADERS if name not in headers]

    if entry.scheme == "http" and "strict-transport-security" in missing:
        missing.remove("strict-transport-security")  # HSTS over plain HTTP is ignored

    if len(missing) >= 3:
        ctx.result.report(
            Severity.LOW,
            f"{len(missing)} security headers missing",
            asset=entry.url,
            detail="The response omits several headers that browsers use as "
                   "defence in depth: "
                   + "; ".join(f"{h} ({SECURITY_HEADERS[h]})" for h in missing),
            evidence=", ".join(missing),
            chakra="ARJUNA",
            remediation="Set the missing headers at the edge so every response "
                        "carries them.",
            references=["https://owasp.org/www-project-secure-headers/"],
        )

    cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    insecure = [
        c.split("=", 1)[0]
        for c in cookies
        if "httponly" not in c.lower() or (entry.scheme == "https" and "secure" not in c.lower())
    ]
    if insecure:
        ctx.result.report(
            Severity.LOW,
            "Session cookies set without HttpOnly or Secure",
            asset=entry.url,
            detail="Cookies missing HttpOnly are readable by injected script, "
                   "and cookies missing Secure can be sent over plain HTTP.",
            evidence=", ".join(shuddhi.sanitize(c, max_len=60) for c in insecure[:5]),
            chakra="ARJUNA",
            remediation="Set HttpOnly, Secure and an appropriate SameSite on "
                        "every session cookie.",
        )


async def _check_quick_wins(ctx: Context, entry: Subdomain) -> None:
    """Request the handful of paths that are outright exposures when present."""
    for path, severity, title, must_contain in QUICK_WINS:
        if ctx.cancelled():
            return
        url = f"{entry.scheme}://{entry.host}{path}"
        resp = await ctx.http.get(url, follow_redirects=False)
        if resp is None or resp.status_code != 200:
            continue
        try:
            body = resp.text[:8000]
        except (UnicodeDecodeError, ValueError):
            body = ""
        if must_contain and must_contain.lower() not in body.lower():
            continue
        # An HTML page where a config file was requested is a soft 404.
        if path not in ("/graphql", "/.well-known/security.txt") and (
            "<html" in body[:400].lower()
        ):
            continue

        ctx.result.report(
            severity,
            title,
            asset=url,
            detail=f"{url} returned HTTP 200 with content matching a real "
                   f"{path} rather than an error page. Files like this disclose "
                   "source history, credentials or internal configuration "
                   "directly to anyone who requests them.",
            evidence=shuddhi.sanitize(body[:200].replace("\n", " "), max_len=200),
            chakra="ARJUNA",
            remediation=f"Block {path} at the web server or remove it from the "
                        "deployed document root.",
        )
        ctx.progress.hit("http", f"{title} → {url}")


async def run(ctx: Context) -> None:
    res = ctx.result
    key = "http"
    targets = res.hosts_resolved()

    if not targets:
        ctx.progress.note(key, "no resolved hosts to probe")
        return

    if len(targets) > ctx.cfg.max_probe_hosts:
        ctx.progress.note(
            key,
            f"limiting to {ctx.cfg.max_probe_hosts} of {len(targets)} hosts "
            "(raise with --max-probe-hosts or --deep)",
        )
        targets = targets[: ctx.cfg.max_probe_hosts]

    # ── Pass 1: what answers at all ───────────────────────────────────────
    ctx.progress.task(key, f"Probing {len(targets)} hosts", total=len(targets))
    sem = asyncio.Semaphore(ctx.cfg.concurrency)

    async def probe(entry: Subdomain) -> None:
        if ctx.cancelled():
            ctx.progress.advance(key)
            return
        async with sem:
            await _probe_host(ctx, entry)
        ctx.progress.advance(key)
        if entry.alive:
            label = f"[{entry.status}] {entry.host}"
            if entry.title:
                label += f" — {entry.title[:50]}"
            ctx.progress.hit(key, label)

    await asyncio.gather(*(probe(e) for e in targets))
    alive = res.hosts_alive()
    ctx.progress.note(key, f"{len(alive)} of {len(targets)} hosts answered")

    if not alive:
        ctx.progress.chakra_done(key, "no hosts answered")
        return

    # ── Pass 2: per-host checks on the hosts that answered ────────────────
    ctx.progress.task(key, f"Auditing {len(alive)} live hosts", total=len(alive) * 2)

    async def audit(entry: Subdomain) -> None:
        if ctx.cancelled():
            return
        async with sem:
            await _check_cors(ctx, entry)
            ctx.progress.advance(key)
            await _check_quick_wins(ctx, entry)
            ctx.progress.advance(key)

    await asyncio.gather(*(audit(e) for e in alive))

    # ── Interesting-status roll-up ────────────────────────────────────────
    gated = [e for e in alive if e.status in (401, 403)]
    if gated:
        res.report(
            Severity.INFO,
            f"{len(gated)} hosts answer but refuse access (401/403)",
            asset=ctx.target,
            detail="These hosts exist and respond but gate their content. They "
                   "are the highest-value targets for authentication and "
                   "authorisation testing, because something is deliberately "
                   "being protected there.",
            evidence=", ".join(f"{e.host} [{e.status}]" for e in gated[:15]),
            chakra="ARJUNA",
        )

    broken = [e for e in alive if e.status and e.status >= 500]
    if broken:
        res.report(
            Severity.LOW,
            f"{len(broken)} hosts return server errors (5xx)",
            asset=ctx.target,
            detail="A server error on a first request often means an "
                   "unconfigured virtual host or a crashing application. Error "
                   "pages frequently include stack traces and internal paths.",
            evidence=", ".join(f"{e.host} [{e.status}]" for e in broken[:15]),
            chakra="ARJUNA",
        )

    tech_counts: dict[str, int] = {}
    for entry in alive:
        for tech in entry.tech:
            tech_counts[tech] = tech_counts.get(tech, 0) + 1
    res.infra["technologies"] = dict(
        sorted(tech_counts.items(), key=lambda kv: -kv[1])
    )

    ctx.progress.chakra_done(
        key, f"{len(alive)} live · {len(tech_counts)} technologies identified"
    )
