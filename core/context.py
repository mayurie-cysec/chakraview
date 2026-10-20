"""Configuration, progress sink and the context object passed to every chakra.

A chakra gets exactly one argument — a Context — and reports everything it
learns onto ctx.result. It never prints. Progress goes through ctx.progress,
which the CLI backs with a rich display and the web server backs with a
server-sent-event stream, so the same module code drives both front ends.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable

from core.models import ScanResult

# Canonical chakra order. The CLI, the web dashboard and --only/--skip all
# read this list, so adding a module here is the only wiring step needed.
CHAKRAS: list[dict[str, str]] = [
    {"key": "github",   "num": "I",    "icon": "🏹", "name": "SHAKUNI",     "title": "SHAKUNI'S STRATEGY",      "sub": "GitHub OSINT — architects, repositories and leaked secrets"},
    {"key": "infra",    "num": "II",   "icon": "👁",  "name": "SANJAYA",     "title": "SANJAYA'S DRISHTI",       "sub": "Infrastructure — addresses, ASN, hosting and CDN/WAF detection"},
    {"key": "dns",      "num": "III",  "icon": "🕉",  "name": "DRONA",       "title": "DRONA'S INSTRUCTION",     "sub": "DNS records, mail-spoofing posture and zone-transfer exposure"},
    {"key": "archive",  "num": "IV",   "icon": "🏺", "name": "ASHWATTHAMA", "title": "ASHWATTHAMA'S MEMORY",    "sub": "Wayback archaeology — paths and parameters time forgot"},
    {"key": "subs",     "num": "V",    "icon": "🛡",  "name": "KARNA",       "title": "KARNA'S LOGIC",           "sub": "Subdomain enumeration — passive sources plus resolved bruteforce"},
    {"key": "http",     "num": "VI",   "icon": "🎯", "name": "ARJUNA",      "title": "ARJUNA'S AIM",            "sub": "HTTP probing — status, titles, technology and exposed files"},
    {"key": "takeover", "num": "VII",  "icon": "🏴", "name": "EKALAVYA",    "title": "EKALAVYA'S CLAIM",        "sub": "Dangling CNAME and subdomain-takeover fingerprinting"},
    {"key": "ports",    "num": "VIII", "icon": "⚔",  "name": "ABHIMANYU",   "title": "ABHIMANYU'S BREACH",      "sub": "Port scanning — exposed services behind the formation"},
    {"key": "js",       "num": "IX",   "icon": "📿", "name": "SAHADEVA",    "title": "SAHADEVA'S KNOWLEDGE",    "sub": "JavaScript mining — hidden endpoints and embedded secrets"},
    {"key": "dorks",    "num": "X",    "icon": "🔥", "name": "BRAHMASTRA",  "title": "THE BRAHMASTRA UNLEASHED","sub": "Precision dork arsenal for Google, GitHub, Shodan and Censys"},
]

CHAKRA_KEYS: list[str] = [c["key"] for c in CHAKRAS]
CHAKRA_BY_KEY: dict[str, dict[str, str]] = {c["key"]: c for c in CHAKRAS}

# Modules that reach out to the target directly. --passive-only drops these so
# the scan stays entirely within third-party data sources.
ACTIVE_CHAKRAS = {"subs", "http", "takeover", "ports", "js"}

PORT_PROFILES: dict[str, list[int]] = {
    "top10": [21, 22, 25, 80, 443, 3306, 3389, 5432, 6379, 8080],
    "top25": [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521,
        3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
    ],
    "top100": [
        21, 22, 23, 25, 53, 69, 79, 80, 81, 88, 110, 111, 123, 135, 139, 143,
        161, 389, 443, 445, 465, 500, 512, 513, 514, 515, 587, 623, 631, 636,
        873, 902, 989, 990, 993, 995, 1080, 1099, 1433, 1521, 1723, 1883,
        2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 2379,
        3000, 3128, 3268, 3306, 3389, 4040, 4443, 4444, 4567, 4848, 5000,
        5432, 5601, 5672, 5900, 5984, 5985, 6379, 6443, 7001, 7077, 7474,
        8000, 8008, 8009, 8080, 8081, 8088, 8089, 8161, 8443, 8500, 8686,
        8888, 9000, 9001, 9042, 9092, 9200, 9300, 9443, 10000, 11211, 15672,
        27017, 27018, 50070,
    ],
}


@dataclass
class Config:
    """Everything the operator chose, resolved and validated."""

    domain: str
    out_dir: str = "reports"
    formats: list[str] = field(default_factory=lambda: ["txt"])
    concurrency: int = 50
    timeout: float = 10.0
    retries: int = 1
    wordlist: str = ""
    only: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)
    passive_only: bool = False
    ports_profile: str = "top25"
    custom_ports: list[int] = field(default_factory=list)
    max_probe_hosts: int = 400
    max_js_hosts: int = 15
    deep: bool = False
    github_token: str = ""
    plain: bool = False
    quiet: bool = False
    no_banner: bool = False
    verify_tls: bool = False

    def __post_init__(self) -> None:
        if not self.github_token:
            self.github_token = os.environ.get("GITHUB_TOKEN", "").strip()
        if self.deep:
            self.ports_profile = (
                "top100" if self.ports_profile == "top25" else self.ports_profile
            )
            self.max_probe_hosts = max(self.max_probe_hosts, 2000)
            self.max_js_hosts = max(self.max_js_hosts, 40)

    @property
    def ports(self) -> list[int]:
        if self.custom_ports:
            return sorted(set(self.custom_ports))
        return PORT_PROFILES.get(self.ports_profile, PORT_PROFILES["top25"])

    def enabled(self, key: str) -> tuple[bool, str]:
        """Return (should_run, reason_if_not)."""
        if self.only and key not in self.only:
            return False, "not in --only"
        if key in self.skip:
            return False, "--skip"
        if self.passive_only and key in ACTIVE_CHAKRAS:
            return False, "--passive-only"
        return True, ""

    def active_chakras(self) -> list[str]:
        return [k for k in CHAKRA_KEYS if self.enabled(k)[0]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "formats": self.formats,
            "concurrency": self.concurrency,
            "timeout": self.timeout,
            "wordlist": self.wordlist or "built-in",
            "ports": self.ports_profile,
            "passive_only": self.passive_only,
            "deep": self.deep,
            "chakras": self.active_chakras(),
            "github_auth": bool(self.github_token),
        }


class ProgressSink:
    """No-op progress target. Subclasses render or stream these events."""

    def chakra_start(self, key: str) -> None: ...

    def chakra_done(self, key: str, summary: str = "") -> None:
        """Called by a module with what it found. May be called more than once."""

    def chakra_elapsed(self, key: str, seconds: float) -> None:
        """Called by the engine once a chakra returns. Never carries findings."""

    def chakra_skip(self, key: str, reason: str) -> None: ...

    def task(self, key: str, label: str, total: int | None = None) -> None:
        """Declare or relabel the current unit of work inside a chakra."""

    def advance(self, key: str, amount: int = 1) -> None: ...

    def hit(self, key: str, text: str) -> None:
        """A live result worth showing the operator the moment it is found."""

    def note(self, key: str, text: str) -> None: ...

    def finding(self, key: str, severity: str, title: str, asset: str) -> None: ...


@dataclass
class Context:
    result: ScanResult
    cfg: Config
    http: Any  # core.net.HttpClient
    resolver: Any  # core.net.Resolver
    progress: ProgressSink = field(default_factory=ProgressSink)
    cancelled: Callable[[], bool] = field(default=lambda: False)

    @property
    def target(self) -> str:
        return self.cfg.domain
