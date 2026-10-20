"""
KARNA — subdomain enumeration.

The original version only brute-forced a wordlist, which finds the hosts you
already guessed and nothing else. This runs ten passive sources first
(certificate transparency, passive DNS, archives, URL scans), merges them
with an optional bruteforce, and resolves everything through one cache.

Two details matter more than the source count. Wildcard DNS is detected up
front, so a domain answering *.target.com does not report every candidate as
live. And every hostname is normalised and validated before it is resolved,
because passive sources return attacker-controlled strings.
"""

from __future__ import annotations

import asyncio
import json
import os
import re

from core.context import Context
from core.models import Severity
from core.net import apex_domain
from modules import shuddhi

# Curated high-signal list, used when no wordlist file is supplied. These are
# the names that actually turn up something worth reporting.
CRITICAL_SUBS: list[str] = [
    # Admin & management
    "admin", "administrator", "admins", "adminpanel", "admin1", "admin2",
    "cpanel", "whm", "plesk", "directadmin", "webadmin", "sysadmin",
    "manager", "manage", "management", "control", "controlpanel",
    "dashboard", "panel", "portal", "console", "webpanel", "backoffice",
    # Development & staging
    "dev", "dev1", "dev2", "dev3", "development", "develop", "devops",
    "staging", "stage", "stg", "stg1", "stg2", "nonprod",
    "test", "test1", "test2", "testing", "testenv", "tst",
    "beta", "beta1", "beta2", "alpha", "sandbox", "sbx",
    "uat", "qa", "qa1", "qa2", "qat", "preprod", "pre-prod", "preview",
    "demo", "demo1", "demo2", "poc", "lab", "labs", "local", "localhost",
    # API & services
    "api", "api1", "api2", "api3", "apiv1", "apiv2", "apiv3", "api-v1",
    "apis", "api-dev", "api-staging", "api-test", "api-prod", "api-gateway",
    "rest", "graphql", "grpc", "soap", "ws", "wss", "websocket", "socket",
    "service", "services", "microservice", "gateway", "gw", "edge",
    # Authentication & identity
    "auth", "auth1", "auth2", "authentication", "authorize", "authz",
    "login", "logout", "signin", "signup", "register", "account", "accounts",
    "sso", "saml", "oauth", "oauth2", "openid", "oidc", "identity", "idp",
    "2fa", "mfa", "otp", "password", "passwd", "reset", "forgot",
    "ldap", "ldaps", "ad", "activedirectory", "radius", "keycloak", "okta",
    # Infrastructure & network
    "vpn", "vpn1", "vpn2", "vpn3", "ssl-vpn", "sslvpn", "remote", "access",
    "rdp", "rds", "citrix", "workspace", "horizon", "anyconnect", "pulse",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "resolver",
    "mx", "mx1", "mx2", "smtp", "smtps", "imap", "imaps", "pop", "pop3",
    "mail", "mail1", "mail2", "webmail", "email", "owa", "mailserver",
    "exchange", "autodiscover", "autoconfig", "outlook", "zimbra",
    "proxy", "proxy1", "proxy2", "wpad", "pac", "squid", "socks",
    "fw", "firewall", "router", "switch", "pfsense", "opnsense",
    "lb", "loadbalancer", "haproxy", "nginx", "apache", "traefik", "f5",
    # DevOps & CI/CD
    "jenkins", "jenkins1", "jenkins2", "ci", "cd", "cicd", "build", "builds",
    "gitlab", "git", "github", "gitea", "gogs", "bitbucket", "svn",
    "jira", "confluence", "wiki", "docs", "documentation", "readthedocs",
    "sonar", "sonarqube", "nexus", "artifactory", "registry", "harbor",
    "docker", "k8s", "kubernetes", "rancher", "portainer", "openshift",
    "ansible", "puppet", "chef", "terraform", "vault", "consul", "nomad",
    "grafana", "kibana", "elastic", "elasticsearch", "logstash", "opensearch",
    "prometheus", "alertmanager", "datadog", "splunk", "graylog", "loki",
    "zabbix", "nagios", "icinga", "prtg", "monitor", "monitoring", "metrics",
    "airflow", "argocd", "spinnaker", "octopus", "teamcity", "bamboo",
    # Database & cache
    "db", "db1", "db2", "db3", "database", "databases", "sql",
    "mysql", "postgres", "postgresql", "pgsql", "mongo", "mongodb",
    "redis", "memcache", "memcached", "cassandra", "couchdb", "neo4j",
    "mssql", "oracle", "mariadb", "phpmyadmin", "adminer", "pgadmin",
    "clickhouse", "influx", "influxdb", "timescale", "snowflake",
    # Storage & files
    "ftp", "ftp1", "ftp2", "sftp", "ftps", "tftp", "scp",
    "files", "file", "upload", "uploads", "download", "downloads", "share",
    "storage", "store", "backup", "backups", "bak", "dump", "dumps",
    "media", "static", "assets", "cdn", "content", "images", "img", "video",
    "s3", "blob", "bucket", "buckets", "archive", "archives", "nas",
    "minio", "swift", "ceph",
    # Internal & corporate
    "internal", "intranet", "extranet", "corp", "corporate", "office",
    "hr", "helpdesk", "support", "ticket", "tickets", "crm", "servicedesk",
    "erp", "finance", "accounting", "billing", "invoice", "pay", "payment",
    "payments", "checkout", "cart", "shop", "store", "ecommerce", "orders",
    "app", "app1", "app2", "apps", "application", "web", "web1", "web2",
    "www", "www1", "www2", "www3", "m", "mobile", "wap", "touch",
    "partner", "partners", "vendor", "vendors", "supplier", "client",
    "clients", "customer", "customers", "members", "employee", "staff",
    # Cloud & hosting
    "aws", "azure", "gcp", "cloud", "cloud1", "cloud2", "openstack",
    "heroku", "digitalocean", "linode", "vultr", "netlify", "vercel",
    "server", "server1", "server2", "server3", "host", "hosting", "srv",
    "vps", "dedicated", "shared", "node", "node1", "node2", "cluster",
    # Security
    "waf", "ids", "ips", "siem", "soc", "soar", "edr", "av",
    "pentest", "scan", "scanner", "security", "sec", "secops", "appsec",
    "cert", "ssl", "tls", "ca", "pki", "ocsp", "crl", "hsm",
    # Communication
    "chat", "slack", "teams", "meet", "zoom", "jitsi", "mattermost",
    "rocketchat", "irc", "xmpp", "sip", "voip", "pbx", "asterisk",
    "conference", "webinar", "stream", "streaming", "live", "broadcast",
    # Marketing & content
    "news", "blog", "blogs", "forum", "forums", "community", "events",
    "careers", "jobs", "press", "about", "contact", "help", "faq",
    "landing", "lp", "promo", "campaign", "track", "tracking", "analytics",
    "ads", "adserver", "pixel", "tag", "gtm", "matomo", "piwik",
    # Versions, states & misc
    "old", "new", "legacy", "deprecated", "v1", "v2", "v3", "v4",
    "test-api", "dev-api", "stage-api", "prod", "production", "live",
    "secret", "hidden", "private", "public", "temp", "tmp", "misc",
    "status", "health", "healthz", "ping", "heartbeat", "uptime", "probe",
    "redirect", "link", "links", "short", "url", "go", "r", "l",
    "search", "solr", "sphinx", "algolia", "meili",
    "queue", "mq", "rabbitmq", "kafka", "activemq", "sqs", "celery",
    "cache", "varnish", "squid-cache",
    "mgmt", "ops", "noc", "infra", "platform", "core", "internal-api",
    "integration", "integrations", "webhook", "webhooks", "callback",
    "third-party", "external", "proxy-api", "bridge", "connector",
]


# ── Passive sources ───────────────────────────────────────────────────────
# Each returns a set of hostnames. A source that is down, rate-limited or has
# changed its response format returns an empty set rather than breaking the
# scan, because these are third-party services with no uptime guarantee.
#
# Every endpoint below was verified to answer without an API key. Sources
# that now demand one (SecurityTrails, VirusTotal, LeakIX) stay in the list
# but only run when their key is present in the environment.


def _in_scope(host: str, domain: str) -> bool:
    return bool(host) and (host == domain or host.endswith(f".{domain}"))


async def _crtsh(ctx: Context, domain: str) -> set[str]:
    """Certificate transparency via crt.sh — the richest source when it is up.

    crt.sh returns 502 under load often enough that it is worth extra
    attempts here rather than losing the source for the whole scan.
    """
    hosts: set[str] = set()
    data = None
    for attempt in range(2):
        data = await ctx.http.json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=40.0)
        if data is not None:
            break
        await asyncio.sleep(1.5)
    if not isinstance(data, list):
        return hosts
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            for line in str(entry.get(field) or "").splitlines():
                host = shuddhi.normalise_host(line)
                if _in_scope(host, domain):
                    hosts.add(host)
    return hosts


async def _certspotter(ctx: Context, domain: str) -> set[str]:
    """Second CT log view — catches certificates crt.sh has not indexed yet."""
    hosts: set[str] = set()
    data = await ctx.http.json(
        "https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    if not isinstance(data, list):
        return hosts
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for name in entry.get("dns_names") or []:
            host = shuddhi.normalise_host(name)
            if _in_scope(host, domain):
                hosts.add(host)
    return hosts


async def _subdomain_center(ctx: Context, domain: str) -> set[str]:
    """api.subdomain.center aggregate — large, free, no key."""
    data = await ctx.http.json(f"https://api.subdomain.center/?domain={domain}", timeout=40.0)
    if not isinstance(data, list):
        return set()
    return {
        h for h in (shuddhi.normalise_host(x) for x in data) if _in_scope(h, domain)
    }


async def _otx(ctx: Context, domain: str) -> set[str]:
    """AlienVault OTX.

    The passive_dns section started requiring authentication, but url_list
    still answers anonymously and carries a hostname per observed URL, which
    is the same information for our purposes.
    """
    hosts: set[str] = set()
    base = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"

    if api_key := os.environ.get("OTX_API_KEY", "").strip():
        data = await ctx.http.json(f"{base}/passive_dns", headers={"X-OTX-API-KEY": api_key})
        if isinstance(data, dict):
            for entry in data.get("passive_dns") or []:
                if isinstance(entry, dict):
                    host = shuddhi.normalise_host(entry.get("hostname", ""))
                    if _in_scope(host, domain):
                        hosts.add(host)

    for page in range(1, 4):
        data = await ctx.http.json(f"{base}/url_list?limit=500&page={page}")
        if not isinstance(data, dict):
            break
        rows = data.get("url_list") or []
        for entry in rows:
            if isinstance(entry, dict):
                host = shuddhi.normalise_host(entry.get("hostname", ""))
                if _in_scope(host, domain):
                    hosts.add(host)
        if not data.get("has_next") or not rows:
            break
    return hosts


async def _hackertarget(ctx: Context, domain: str) -> set[str]:
    """HackerTarget hostsearch — plain CSV, generous unauthenticated quota."""
    hosts: set[str] = set()
    text = await ctx.http.text(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not text or "api count exceeded" in text.lower() or text.lower().startswith("error"):
        return hosts
    for line in text.splitlines():
        host = shuddhi.normalise_host(line.split(",")[0])
        if _in_scope(host, domain):
            hosts.add(host)
    return hosts


async def _rapiddns(ctx: Context, domain: str) -> set[str]:
    """RapidDNS HTML table scrape — no API, but strong coverage."""
    hosts: set[str] = set()
    text = await ctx.http.text(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=30.0)
    if not text:
        return hosts
    for match in re.findall(r"<td>([^<>\s]+)</td>", text):
        host = shuddhi.normalise_host(match)
        if _in_scope(host, domain):
            hosts.add(host)
    return hosts


async def _urlscan(ctx: Context, domain: str) -> set[str]:
    """urlscan.io search — hosts seen in real recorded page loads."""
    hosts: set[str] = set()
    headers = {}
    if api_key := os.environ.get("URLSCAN_API_KEY", "").strip():
        headers["API-Key"] = api_key
    data = await ctx.http.json(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000", headers=headers
    )
    if not isinstance(data, dict):
        return hosts
    for entry in data.get("results") or []:
        if not isinstance(entry, dict):
            continue
        page = entry.get("page") or {}
        task = entry.get("task") or {}
        for candidate in (page.get("domain", ""), page.get("ptr", ""), task.get("domain", "")):
            host = shuddhi.normalise_host(candidate)
            if _in_scope(host, domain):
                hosts.add(host)
    return hosts


async def _wayback_hosts(ctx: Context, domain: str) -> set[str]:
    """Hostnames in archived URLs — finds staging hosts that died years ago.

    The CDX wildcard goes on the host (`*.domain`), not the path; adding
    `/*` as well makes the query time out on any real domain.
    """
    hosts: set[str] = set()
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=10000"
    )
    text = None
    for attempt in range(2):
        text = await ctx.http.text(url, timeout=40.0)
        if text:
            break
        await asyncio.sleep(1.5)
    if not text:
        return hosts
    for line in text.splitlines():
        host = shuddhi.normalise_host(line)
        if _in_scope(host, domain):
            hosts.add(host)
    return hosts


async def _securitytrails(ctx: Context, domain: str) -> set[str]:
    """SecurityTrails — runs only when SECURITYTRAILS_API_KEY is set."""
    api_key = os.environ.get("SECURITYTRAILS_API_KEY", "").strip()
    if not api_key:
        return set()
    data = await ctx.http.json(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        headers={"APIKEY": api_key},
    )
    if not isinstance(data, dict):
        return set()
    return {
        h for h in (
            shuddhi.normalise_host(f"{sub}.{domain}") for sub in data.get("subdomains") or []
        ) if _in_scope(h, domain)
    }


async def _virustotal(ctx: Context, domain: str) -> set[str]:
    """VirusTotal relations — runs only when VT_API_KEY is set."""
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return set()
    data = await ctx.http.json(
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000",
        headers={"x-apikey": api_key},
    )
    if not isinstance(data, dict):
        return set()
    return {
        h for h in (
            shuddhi.normalise_host(e.get("id", ""))
            for e in data.get("data") or [] if isinstance(e, dict)
        ) if _in_scope(h, domain)
    }


async def _leakix(ctx: Context, domain: str) -> set[str]:
    """LeakIX subdomains — runs only when LEAKIX_API_KEY is set."""
    api_key = os.environ.get("LEAKIX_API_KEY", "").strip()
    if not api_key:
        return set()
    data = await ctx.http.json(
        f"https://leakix.net/api/subdomains/{domain}",
        headers={"api-key": api_key, "Accept": "application/json"},
    )
    if not isinstance(data, list):
        return set()
    return {
        h for h in (
            shuddhi.normalise_host(e.get("subdomain", ""))
            for e in data if isinstance(e, dict)
        ) if _in_scope(h, domain)
    }


# Order is cosmetic — they all run concurrently.
PASSIVE_SOURCES: list[tuple[str, object]] = [
    ("crt.sh", _crtsh),
    ("certspotter", _certspotter),
    ("subdomain.center", _subdomain_center),
    ("otx", _otx),
    ("hackertarget", _hackertarget),
    ("rapiddns", _rapiddns),
    ("urlscan", _urlscan),
    ("wayback", _wayback_hosts),
    ("securitytrails", _securitytrails),
    ("virustotal", _virustotal),
    ("leakix", _leakix),
]

# Sources that do nothing without a key, so the UI can say so instead of
# reporting them as sources that found nothing.
KEYED_SOURCES: dict[str, str] = {
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "virustotal": "VT_API_KEY",
    "leakix": "LEAKIX_API_KEY",
}


def load_wordlist(path: str = "") -> list[str]:
    """Operator wordlist if given, otherwise the curated built-in list."""
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                words = [
                    w for w in (line.strip().lower() for line in handle)
                    if w and not w.startswith("#")
                ]
            if words:
                return sorted(set(words))
        except OSError:
            pass
    return sorted(set(CRITICAL_SUBS))


async def run(ctx: Context) -> None:
    domain = ctx.target
    res = ctx.result
    key = "subs"
    apex = apex_domain(domain)

    # ── Passive collection ────────────────────────────────────────────────
    ctx.progress.task(key, "Querying passive sources", total=len(PASSIVE_SOURCES))
    source_counts: dict[str, int] = {}

    async def collect(name: str, fn) -> None:
        try:
            hosts = await fn(ctx, apex)
        except Exception as exc:  # a broken source must not end the scan
            res.errors.append(f"karna/{name}: {type(exc).__name__}")
            hosts = set()
        new = 0
        for host in hosts:
            if host not in res.subdomains:
                new += 1
            res.add_subdomain(host, name)
        source_counts[name] = len(hosts)
        ctx.progress.advance(key)
        if hosts:
            ctx.progress.hit(key, f"{name}: {len(hosts)} host(s), {new} new")

    await asyncio.gather(*(collect(name, fn) for name, fn in PASSIVE_SOURCES))
    passive_total = len(res.subdomains)
    ctx.progress.note(key, f"{passive_total} unique hosts from passive sources")

    # ── Wildcard detection, before any bruteforce is trusted ──────────────
    ctx.progress.task(key, "Checking for wildcard DNS")
    wildcard_ips = await ctx.resolver.wildcard_ips(apex)
    if wildcard_ips:
        ctx.progress.note(key, f"wildcard DNS active → {len(wildcard_ips)} IP(s) filtered")
        res.report(
            Severity.INFO,
            "Wildcard DNS record in use",
            asset=apex,
            detail="Every non-existent name under this domain resolves, so "
                   "bruteforce results that land on the wildcard addresses are "
                   "not real hosts. Those answers were filtered out of the "
                   "results below.",
            evidence=", ".join(sorted(wildcard_ips)[:8]),
            chakra="KARNA",
        )

    # ── Bruteforce ────────────────────────────────────────────────────────
    if not ctx.cfg.passive_only:
        words = load_wordlist(ctx.cfg.wordlist)
        candidates = [
            f"{w}.{apex}" for w in words
            if shuddhi.valid_hostname(f"{w}.{apex}") and f"{w}.{apex}" not in res.subdomains
        ]
        ctx.progress.task(key, f"Bruteforcing {len(candidates)} names", total=len(candidates))

        found_brute = 0
        sem = asyncio.Semaphore(max(10, ctx.cfg.concurrency * 2))

        async def probe(host: str) -> None:
            nonlocal found_brute
            if ctx.cancelled():
                ctx.progress.advance(key)
                return
            async with sem:
                ips = await ctx.resolver.resolve_a(host)
            ctx.progress.advance(key)
            if not ips or (wildcard_ips and set(ips).issubset(wildcard_ips)):
                return
            entry = res.add_subdomain(host, "bruteforce")
            entry.ips = ips
            found_brute += 1
            ctx.progress.hit(key, f"{host} → {', '.join(ips[:2])}")

        await asyncio.gather(*(probe(h) for h in candidates))
        source_counts["bruteforce"] = found_brute
        ctx.progress.note(key, f"{found_brute} live host(s) from bruteforce")

    # ── Resolve everything collected passively ────────────────────────────
    unresolved = [s for s in res.subdomains.values() if not s.ips]
    if unresolved:
        ctx.progress.task(key, f"Resolving {len(unresolved)} collected hosts", total=len(unresolved))
        sem = asyncio.Semaphore(max(10, ctx.cfg.concurrency * 2))

        async def resolve(entry) -> None:
            if ctx.cancelled():
                ctx.progress.advance(key)
                return
            async with sem:
                ips = await ctx.resolver.resolve_a(entry.host)
                cname = await ctx.resolver.cname(entry.host)
            ctx.progress.advance(key)
            if wildcard_ips and ips and set(ips).issubset(wildcard_ips):
                return
            entry.ips = ips
            entry.cname = cname

        await asyncio.gather(*(resolve(e) for e in unresolved))

    resolved = res.hosts_resolved()
    res.dns.setdefault("wildcard_ips", sorted(wildcard_ips))
    res.infra.setdefault("subdomain_sources", source_counts)

    if resolved:
        res.report(
            Severity.INFO,
            f"{len(resolved)} live subdomains discovered",
            asset=apex,
            detail=f"{len(res.subdomains)} unique names were collected from "
                   f"{len([s for s, c in source_counts.items() if c])} sources, "
                   f"of which {len(resolved)} resolve. Each live host is its own "
                   "attack surface and should be probed and triaged separately.",
            evidence=", ".join(s.host for s in resolved[:15]),
            chakra="KARNA",
        )

    ctx.progress.chakra_done(
        key, f"{len(res.subdomains)} collected · {len(resolved)} resolving"
    )
