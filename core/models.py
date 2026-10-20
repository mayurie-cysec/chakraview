"""Data model shared by every chakra.

Modules do not print findings themselves and they do not decide how a finding
is rendered. They append Finding objects to the ScanResult and the UI/report
layer takes it from there, which is what lets the same scan produce a terminal
table, a JSON file and an HTML page without any module knowing about it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def style(self) -> str:
        """Rich style name for this severity (defined in core.ui.CHAKRA_THEME)."""
        return f"sev.{self.name.lower()}"

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            return cls.INFO


@dataclass
class Finding:
    """One actionable observation, de-duplicated by (chakra, title, asset)."""

    severity: Severity
    title: str
    asset: str = ""
    detail: str = ""
    evidence: str = ""
    chakra: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.chakra, self.title, self.asset)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass
class Subdomain:
    """A discovered hostname plus whatever we learned about it later."""

    host: str
    ips: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    cname: str = ""

    # Filled in by arjuna (HTTP probe)
    url: str = ""
    status: int | None = None
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    content_length: int | None = None
    redirect: str = ""
    scheme: str = ""

    # Filled in by abhimanyu (port scan)
    ports: list[int] = field(default_factory=list)

    @property
    def alive(self) -> bool:
        return self.status is not None

    @property
    def resolved(self) -> bool:
        return bool(self.ips)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["sources"] = sorted(self.sources)
        return data


@dataclass
class ScanResult:
    """Everything one ChakraView run produced. The single source of truth."""

    target: str
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    args: dict[str, Any] = field(default_factory=dict)

    findings: list[Finding] = field(default_factory=list)
    subdomains: dict[str, Subdomain] = field(default_factory=dict)

    github: dict[str, Any] = field(default_factory=dict)
    infra: dict[str, Any] = field(default_factory=dict)
    dns: dict[str, Any] = field(default_factory=dict)
    archive: dict[str, Any] = field(default_factory=dict)
    takeover: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    dorks: dict[str, Any] = field(default_factory=dict)

    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # Set by a front end that wants findings as they happen (the web dashboard
    # streams them live). Not serialised.
    on_finding: Any = None

    # ---------------------------------------------------------------- findings
    def add(self, finding: Finding) -> Finding | None:
        """Record a finding unless an identical one is already present."""
        if any(f.key == finding.key for f in self.findings):
            return None
        self.findings.append(finding)
        if self.on_finding is not None:
            try:
                self.on_finding(finding)
            except Exception:
                # A broken listener must never cost us the finding itself.
                pass
        return finding

    def report(
        self,
        severity: Any,
        title: str,
        *,
        asset: str = "",
        detail: str = "",
        evidence: str = "",
        chakra: str = "",
        remediation: str = "",
        references: list[str] | None = None,
    ) -> Finding | None:
        return self.add(
            Finding(
                severity=Severity.parse(severity),
                title=title,
                asset=asset or self.target,
                detail=detail,
                evidence=evidence,
                chakra=chakra,
                remediation=remediation,
                references=references or [],
            )
        )

    def findings_sorted(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.chakra, f.title, f.asset),
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in reversed(list(Severity))}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    @property
    def risk_score(self) -> int:
        """0-100 weighted score. Caps so one noisy class cannot pin it at 100."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 12,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        per_class: dict[Severity, int] = {}
        for f in self.findings:
            per_class[f.severity] = per_class.get(f.severity, 0) + 1
        score = 0
        for sev, count in per_class.items():
            score += weights[sev] * min(count, 4)
        return min(100, score)

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score >= 70:
            return "CRITICAL"
        if score >= 45:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "CLEAN"

    # ------------------------------------------------------------- subdomains
    def add_subdomain(self, host: str, source: str) -> Subdomain:
        host = host.strip().lower().lstrip("*.").rstrip(".")
        existing = self.subdomains.get(host)
        if existing is None:
            existing = Subdomain(host=host)
            self.subdomains[host] = existing
        existing.sources.add(source)
        return existing

    def hosts_resolved(self) -> list[Subdomain]:
        return [s for s in self.subdomains.values() if s.resolved]

    def hosts_alive(self) -> list[Subdomain]:
        return [s for s in self.subdomains.values() if s.alive]

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.started_at)),
            "duration_seconds": round(self.duration, 1),
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "severity_counts": self.severity_counts(),
            "args": self.args,
            "findings": [f.to_dict() for f in self.findings_sorted()],
            "subdomains": [
                s.to_dict() for s in sorted(self.subdomains.values(), key=lambda x: x.host)
            ],
            "github": self.github,
            "infra": self.infra,
            "dns": self.dns,
            "archive": self.archive,
            "takeover": self.takeover,
            "secrets": self.secrets,
            "endpoints": sorted(set(self.endpoints)),
            "dorks": self.dorks,
            "skipped": self.skipped,
            "errors": self.errors,
        }
