"""Terminal front end.

Everything the operator sees in a shell is built here. The important change
from v1 is that the progress shown is real: bars advance from the module's own
counters, and results print the moment they are found. The previous version
replayed a fake radar sweep after the scan had already finished, which looked
busy and told the operator nothing.

Purple/black palette from core.theme, matching the web UI.
"""

from __future__ import annotations

import itertools
import math
import time

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from core import theme as T
from core.context import CHAKRA_BY_KEY, Config, ProgressSink
from core.models import ScanResult, Severity
from modules import shuddhi

CHAKRA_THEME = Theme(T.RICH_STYLES)

BANNER = r"""
 ██████╗██╗  ██╗ █████╗ ██╗  ██╗██████╗  █████╗ ██╗   ██╗██╗███████╗██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔══██╗██╔══██╗██║   ██║██║██╔════╝██║    ██║
██║     ███████║███████║█████╔╝ ██████╔╝███████║██║   ██║██║█████╗  ██║ █╗ ██║
██║     ██╔══██║██╔══██║██╔═██╗ ██╔══██╗██╔══██║╚██╗ ██╔╝██║██╔══╝  ██║███╗██║
╚██████╗██║  ██║██║  ██║██║  ██╗██║  ██║██║  ██║ ╚████╔╝ ██║███████╗╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝
"""

# The Sudarshana Chakra is drawn by walking the grid and asking each cell
# where it falls in polar space, rather than by plotting points along a path.
# Sampling this way fills the rim and the spokes evenly, so the wheel reads as
# a solid object that turns instead of a scatter of glyphs that flickers.
_RIM_GLYPHS = ["◈", "✦", "◆", "✧"]
_SPOKE_COUNT = 8
_TAU = math.pi * 2


def _chakra_frame(tick: int, radius: int = 8) -> Text:
    """One frame of the turning chakra. Advance `tick` to rotate it."""
    phase = tick * 0.22
    sector = _TAU / _SPOKE_COUNT
    lines: list[tuple[str, str]] = []

    for grid_y in range(-radius, radius + 1):
        row: list[str] = []
        for grid_x in range(-radius * 2, radius * 2 + 1):
            # Terminal cells are about twice as tall as they are wide.
            x, y = grid_x / 2.0, float(grid_y)
            distance = math.hypot(x, y)
            angle = math.atan2(y, x)

            if distance < 0.7:
                row.append("⊙")                              # hub
            elif abs(distance - radius) < 0.55:
                index = int((angle + phase) / sector) % len(_RIM_GLYPHS)
                row.append(_RIM_GLYPHS[index])               # outer rim
            elif abs(distance - radius * 0.58) < 0.45:
                row.append("━")                              # inner ring
            elif distance < radius - 0.7:
                offset = (angle - phase) % sector
                if min(offset, sector - offset) < 0.13:
                    row.append("─" if distance > radius * 0.3 else "·")
                else:
                    row.append(" ")                          # spokes
            else:
                row.append(" ")

        # Colour in bands so the wheel has depth: gold hub, violet body, purple rim.
        band = abs(grid_y)
        if band <= 1:
            style = "cv.gold"
        elif band <= radius // 2:
            style = "cv.violet"
        else:
            style = "cv.purple"
        lines.append(("".join(row).rstrip(), style))

    text = Text()
    for line, style in lines:
        text.append(line + "\n", style=style)
    return text


class TerminalUI(ProgressSink):
    """Renders a scan to a terminal, and is the CLI's ProgressSink."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.plain = cfg.plain
        self.quiet = cfg.quiet
        self.console = Console(
            theme=CHAKRA_THEME,
            no_color=cfg.plain,
            highlight=False,
            soft_wrap=False,
        )
        self._progress: Progress | None = None
        self._task_ids: dict[str, int] = {}
        self._current: str = ""
        self._hits: dict[str, int] = {}

    # ── Framing ───────────────────────────────────────────────────────────

    def banner(self) -> None:
        if self.quiet or self.cfg.no_banner:
            return

        if self.plain:
            self.console.print("ChakraView 2.0 — Strategic Recon Formation")
            return

        self.console.print(Text(BANNER, style="cv.violet"), justify="center")
        self.console.print(
            Text("☸  T H E   S T R A T E G I C   B A T T L E   F O R M A T I O N  ☸",
                 style="cv.lilac"),
            justify="center",
        )
        self.console.print(
            Text("Ten chakras · authorised reconnaissance only", style="cv.faint"),
            justify="center",
        )
        self.console.print()

        # The chakra turns while the formation assembles.
        labels = [
            "Assembling the vyuha",
            "Summoning the ten chakras",
            "Stringing the Gandiva",
            "Arming the Brahmastra",
        ]
        with Live(console=self.console, refresh_per_second=20, transient=True) as live:
            for tick in range(26):
                label = labels[(tick // 7) % len(labels)]
                live.update(
                    Group(
                        Align.center(_chakra_frame(tick)),
                        Align.center(Text(f"{label}…", style="cv.muted")),
                    )
                )
                time.sleep(0.05)

    def target_header(self, target: str, chakra_count: int) -> None:
        if self.quiet:
            return
        table = Table.grid(padding=(0, 2))
        table.add_column(style="cv.muted", justify="right")
        table.add_column(style="cv.text")
        table.add_row("Target", Text(target.upper(), style="cv.target"))
        table.add_row("Started", time.strftime("%Y-%m-%d %H:%M:%S"))
        table.add_row("Chakras", f"{chakra_count} of 10 enabled")
        table.add_row("Concurrency", f"{self.cfg.concurrency} · timeout {self.cfg.timeout:g}s")
        if self.cfg.passive_only:
            table.add_row("Mode", Text("PASSIVE ONLY — no traffic to target", style="cv.warn"))
        if self.cfg.deep:
            table.add_row("Mode", Text("DEEP — expanded limits", style="cv.lilac"))
        self.console.print(
            Panel(table, title="[cv.chakra]TARGET FORTRESS[/]", border_style="cv.border",
                  padding=(1, 2))
        )

    # ── Progress lifecycle ────────────────────────────────────────────────

    def start(self) -> None:
        if self.quiet:
            return
        self._progress = Progress(
            SpinnerColumn("dots", style="cv.lilac"),
            TextColumn("[cv.muted]{task.description}"),
            BarColumn(bar_width=28, style="cv.border", complete_style="cv.violet",
                      finished_style="cv.purple"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        self._progress.start()

    def stop(self) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None

    def _print(self, renderable) -> None:
        """Print above the live progress bars so nothing is overwritten."""
        if self._progress is not None:
            self._progress.console.print(renderable)
        else:
            self.console.print(renderable)

    # ── ProgressSink implementation ───────────────────────────────────────

    def chakra_start(self, key: str) -> None:
        if self.quiet:
            return
        meta = CHAKRA_BY_KEY[key]
        self._current = key
        self._hits[key] = 0
        label = f"{meta['icon']}  CHAKRA {meta['num']} — {meta['title']}"
        self._print("")
        self._print(Rule(Text(label, style="cv.chakra"), style="cv.border", align="left"))
        self._print(Text(f"   {meta['sub']}", style="cv.faint"))

    def task(self, key: str, label: str, total: int | None = None) -> None:
        if self._progress is None:
            return
        description = f"{CHAKRA_BY_KEY[key]['name']:<12} {label}"
        if key in self._task_ids:
            self._progress.update(
                self._task_ids[key], description=description,
                total=total, completed=0,
            )
        else:
            self._task_ids[key] = self._progress.add_task(description, total=total)

    def advance(self, key: str, amount: int = 1) -> None:
        if self._progress is None or key not in self._task_ids:
            return
        self._progress.advance(self._task_ids[key], amount)

    def hit(self, key: str, text: str) -> None:
        if self.quiet:
            return
        self._hits[key] = self._hits.get(key, 0) + 1
        # Past a point, a wall of live hits stops being useful — the tables at
        # the end carry the full set.
        if self._hits[key] > 40:
            if self._hits[key] == 41:
                self._print(Text("     … further results collected silently",
                                 style="cv.faint"))
            return
        self._print(
            Text.assemble(
                ("     ", ""),
                (T.SPARKLE + " ", "cv.sparkle"),
                (shuddhi.sanitize(text, max_len=160), "cv.text"),
            )
        )

    def note(self, key: str, text: str) -> None:
        if self.quiet:
            return
        self._print(
            Text.assemble(
                ("     ", ""),
                ("› ", "cv.purple"),
                (shuddhi.sanitize(text, max_len=200), "cv.muted"),
            )
        )

    def chakra_done(self, key: str, summary: str = "") -> None:
        if self.quiet or not summary:
            return
        if self._progress is not None and key in self._task_ids:
            task = self._progress.tasks[self._task_ids[key]]
            if task.total:
                self._progress.update(self._task_ids[key], completed=task.total)
        self._print(
            Text.assemble(
                ("     ", ""),
                ("✓ ", "cv.ok"),
                (shuddhi.sanitize(summary, max_len=200), "cv.muted"),
            )
        )

    def chakra_elapsed(self, key: str, seconds: float) -> None:
        if self._progress is None or key not in self._task_ids:
            return
        task = self._progress.tasks[self._task_ids[key]]
        if task.total:
            self._progress.update(self._task_ids[key], completed=task.total)

    def chakra_skip(self, key: str, reason: str) -> None:
        if self.quiet:
            return
        meta = CHAKRA_BY_KEY[key]
        self._print(
            Text.assemble(
                ("  ", ""),
                (f"{meta['icon']}  CHAKRA {meta['num']} — {meta['name']}", "cv.faint"),
                ("  skipped: ", "cv.faint"),
                (reason, "cv.faint"),
            )
        )

    # ── Result rendering ──────────────────────────────────────────────────

    def render_results(self, result: ScanResult) -> None:
        self.stop()
        self.console.print()
        self._render_findings(result)
        self._render_hosts(result)
        self._render_dorks(result)
        self._render_summary(result)

    def _render_findings(self, result: ScanResult) -> None:
        findings = result.findings_sorted()
        if not findings:
            self.console.print(
                Panel(
                    Text("No findings recorded. Either the target is genuinely "
                         "quiet, or the chakras that matter were skipped.",
                         style="cv.muted"),
                    title="[cv.chakra]FINDINGS[/]", border_style="cv.border",
                )
            )
            return

        table = Table(
            title=f"[cv.chakra]FINDINGS — {len(findings)} total[/]",
            box=None, expand=True, padding=(0, 1), title_justify="left",
        )
        table.add_column("SEV", width=8, no_wrap=True)
        table.add_column("CHAKRA", width=12, style="cv.purple", no_wrap=True)
        table.add_column("FINDING", ratio=3, overflow="fold")
        table.add_column("ASSET", ratio=2, style="cv.muted", overflow="fold")

        for finding in findings:
            table.add_row(
                Text(finding.severity.label[:8], style=finding.severity.style),
                finding.chakra or "—",
                Text(shuddhi.sanitize(finding.title, max_len=200), style="cv.text"),
                shuddhi.sanitize(finding.asset, max_len=120),
            )
        self.console.print(table)
        self.console.print()

        # Detail blocks for anything a researcher should act on immediately.
        urgent = [f for f in findings if f.severity >= Severity.HIGH]
        for finding in urgent[:12]:
            body = Table.grid(padding=(0, 2))
            body.add_column(style="cv.muted", justify="right", width=12)
            body.add_column(overflow="fold")
            body.add_row("Asset", Text(shuddhi.sanitize(finding.asset, max_len=300),
                                       style="cv.text"))
            body.add_row("Detail", Text(shuddhi.sanitize(finding.detail, max_len=900),
                                        style="cv.text"))
            if finding.evidence:
                body.add_row("Evidence", Text(shuddhi.sanitize(finding.evidence, max_len=400),
                                              style="cv.lilac"))
            if finding.remediation:
                body.add_row("Fix", Text(shuddhi.sanitize(finding.remediation, max_len=400),
                                         style="cv.ok"))
            if finding.references:
                body.add_row("Refs", Text("\n".join(finding.references[:3]), style="cv.faint"))
            self.console.print(
                Panel(
                    body,
                    title=Text.assemble(
                        (f" {finding.severity.label} ", finding.severity.style),
                        (f" {shuddhi.sanitize(finding.title, max_len=120)}", "cv.text"),
                    ),
                    border_style=finding.severity.style,
                    padding=(1, 2),
                )
            )

    def _render_hosts(self, result: ScanResult) -> None:
        alive = sorted(result.hosts_alive(), key=lambda e: (e.status or 999, e.host))
        if not alive:
            return

        table = Table(
            title=f"[cv.chakra]LIVE HOSTS — {len(alive)} responding[/]",
            box=None, expand=True, padding=(0, 1), title_justify="left",
        )
        table.add_column("CODE", width=5, no_wrap=True)
        table.add_column("HOST", ratio=2, overflow="fold")
        table.add_column("TITLE", ratio=2, style="cv.muted", overflow="ellipsis")
        table.add_column("TECH", ratio=2, style="cv.lilac", overflow="fold")
        table.add_column("PORTS", width=18, style="cv.faint", overflow="fold")

        for entry in alive[:80]:
            status = entry.status or 0
            if 200 <= status < 300:
                style = "cv.ok"
            elif status in (401, 403):
                style = "cv.warn"
            elif status >= 500:
                style = "cv.fail"
            else:
                style = "cv.muted"
            table.add_row(
                Text(str(status), style=style),
                Text(shuddhi.sanitize(entry.host, max_len=100), style="cv.text"),
                shuddhi.sanitize(entry.title, max_len=60),
                ", ".join(entry.tech[:4]),
                ", ".join(str(p) for p in entry.ports[:6]),
            )
        if len(alive) > 80:
            table.add_row("", Text(f"… and {len(alive) - 80} more in the report",
                                   style="cv.faint"), "", "", "")
        self.console.print(table)
        self.console.print()

    def _render_dorks(self, result: ScanResult) -> None:
        queries = (result.dorks or {}).get("queries") or []
        if not queries:
            return
        shown = queries[:14]
        table = Table(
            title=f"[cv.chakra]DORK ARSENAL — {len(queries)} queries prepared[/]",
            box=None, expand=True, padding=(0, 1), title_justify="left",
        )
        table.add_column("#", width=4, style="cv.faint", no_wrap=True)
        table.add_column("GROUP", width=22, style="cv.purple", overflow="fold")
        table.add_column("QUERY", ratio=1, overflow="fold")
        for index, dork in enumerate(shown, 1):
            table.add_row(f"{index:02d}", dork["group"],
                          Text(dork["query"], style="cv.text"))
        self.console.print(table)
        self.console.print(
            Text(f"   Full arsenal with clickable Google/Shodan/Censys links is "
                 f"in the HTML and JSON reports.", style="cv.faint")
        )
        self.console.print()

    def _render_summary(self, result: ScanResult) -> None:
        counts = result.severity_counts()
        score = result.risk_score
        label = result.risk_label

        risk_style = {
            "CRITICAL": "sev.critical", "HIGH": "sev.high", "MEDIUM": "sev.medium",
            "LOW": "sev.low", "CLEAN": "cv.ok",
        }[label]

        filled = round(score / 100 * 32)
        meter = Text()
        meter.append("█" * filled, style=risk_style)
        meter.append("░" * (32 - filled), style="cv.border")

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="cv.muted", justify="right", width=22)
        grid.add_column()

        grid.add_row("Risk", Text.assemble(
            (f"{label} ", risk_style), (f"({score}/100)", "cv.muted"), ("  ", ""), meter,
        ))
        severity_line = Text()
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if counts[name]:
                severity_line.append(f"{counts[name]} {name}  ",
                                     style=f"sev.{name.lower()}")
        grid.add_row("Findings", severity_line or Text("none", style="cv.muted"))
        grid.add_row("Subdomains collected", str(len(result.subdomains)))
        grid.add_row("Resolving", str(len(result.hosts_resolved())))
        grid.add_row("Responding to HTTP", str(len(result.hosts_alive())))

        open_ports = (result.infra or {}).get("open_ports") or {}
        if open_ports:
            grid.add_row("Open ports",
                         f"{sum(len(v) for v in open_ports.values())} across "
                         f"{len(open_ports)} host(s)")
        if result.takeover:
            grid.add_row("Takeover candidates",
                         Text(str(len(result.takeover)), style="sev.high"))
        if result.secrets:
            grid.add_row("Secrets in JavaScript",
                         Text(str(len(result.secrets)), style="sev.critical"))
        if result.endpoints:
            grid.add_row("API endpoints recovered", str(len(result.endpoints)))
        technologies = (result.infra or {}).get("technologies") or {}
        if technologies:
            grid.add_row("Technologies", ", ".join(list(technologies)[:8]))
        grid.add_row("Duration", f"{result.duration:.1f}s")
        if result.skipped:
            grid.add_row("Skipped", Text(", ".join(result.skipped[:6]), style="cv.faint"))
        if result.errors:
            grid.add_row("Errors", Text(f"{len(result.errors)} (see report)",
                                        style="cv.warn"))

        self.console.print(
            Panel(grid, title=f"[cv.chakra]BATTLE SUMMARY — {result.target.upper()}[/]",
                  border_style="cv.border", padding=(1, 2))
        )

    def report_saved(self, paths: dict[str, str]) -> None:
        if not paths:
            return
        self.console.print()
        for fmt, path in paths.items():
            self.console.print(
                Text.assemble(
                    ("  ✓ ", "cv.ok"),
                    (f"{fmt.upper():<5} ", "cv.purple"),
                    (path, "cv.text"),
                )
            )

    def closing(self) -> None:
        if self.quiet:
            return
        self.console.print()
        self.console.print(
            Text(f"  {T.SWORD}  The vyuha is mapped. Verify before you report.  {T.SWORD}",
                 style="cv.gold"),
            justify="center",
        )
        self.console.print()

    def error(self, message: str) -> None:
        self.console.print(Text(f"  [!] {message}", style="cv.fail"))
