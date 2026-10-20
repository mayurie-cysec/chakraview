"""Local web server — serves the landing page and drives scans from a browser.

Built on the standard library deliberately. A reconnaissance tool people
clone and run should not need a web framework installed just to open its
dashboard, so this uses ThreadingHTTPServer plus server-sent events. SSE is
the right fit: scan progress only ever flows server to client.

Security posture: the dashboard starts network scans, so whoever can reach
this port can scan arbitrary hosts through it. It binds to 127.0.0.1 unless
told otherwise, warns loudly when bound wider, and refuses targets that do
not normalise to a public hostname.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import os
import queue
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from core.context import CHAKRA_KEYS, CHAKRAS, PORT_PROFILES, Config, ProgressSink
from core.engine import normalise_target, run_scan
from core.report import FORMATS, write_all
from modules import shuddhi

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(ROOT, "web")
REPORT_DIR = os.path.join(ROOT, "reports")

MAX_BODY = 64 * 1024
MAX_CONCURRENT_SCANS = 2
SCAN_RETENTION = 3600  # seconds a finished scan stays downloadable


class Scan:
    """One scan: its config, its event queue, and its result when finished."""

    def __init__(self, scan_id: str, cfg: Config) -> None:
        self.id = scan_id
        self.cfg = cfg
        self.events: queue.Queue = queue.Queue(maxsize=4000)
        self.result = None
        self.reports: dict[str, str] = {}
        self.state = "queued"  # queued | running | done | failed | cancelled
        self.error = ""
        self.started = time.time()
        self.finished = 0.0
        self._stop = threading.Event()

    def emit(self, kind: str, **payload) -> None:
        payload["event"] = kind
        try:
            self.events.put_nowait(payload)
        except queue.Full:
            # A browser that stopped reading must not stall the scan.
            pass

    def stop(self) -> None:
        self._stop.set()

    @property
    def cancelled(self) -> bool:
        return self._stop.is_set()


class SSESink(ProgressSink):
    """Turns module progress callbacks into SSE payloads."""

    def __init__(self, scan: Scan) -> None:
        self.scan = scan
        self._totals: dict[str, int] = {}
        self._done: dict[str, int] = {}

    def chakra_start(self, key: str) -> None:
        self.scan.emit("chakra_start", key=key)

    def chakra_done(self, key: str, summary: str = "") -> None:
        self.scan.emit("chakra_done", key=key, summary=shuddhi.sanitize(summary, max_len=300))

    def chakra_elapsed(self, key: str, seconds: float) -> None:
        self.scan.emit("chakra_elapsed", key=key, seconds=round(seconds, 1))

    def chakra_skip(self, key: str, reason: str) -> None:
        self.scan.emit("chakra_skip", key=key, reason=shuddhi.sanitize(reason, max_len=120))

    def task(self, key: str, label: str, total: int | None = None) -> None:
        self._totals[key] = total or 0
        self._done[key] = 0
        self.scan.emit("task", key=key, label=shuddhi.sanitize(label, max_len=160),
                       total=total or 0)

    def advance(self, key: str, amount: int = 1) -> None:
        self._done[key] = self._done.get(key, 0) + amount
        total = self._totals.get(key, 0)
        # Coalesce: a 50k-candidate bruteforce must not emit 50k events.
        step = max(1, total // 100) if total else 25
        if self._done[key] % step == 0 or (total and self._done[key] >= total):
            self.scan.emit("advance", key=key, done=self._done[key], total=total)

    def hit(self, key: str, text: str) -> None:
        self.scan.emit("hit", key=key, text=shuddhi.sanitize(text, max_len=300))

    def note(self, key: str, text: str) -> None:
        self.scan.emit("note", key=key, text=shuddhi.sanitize(text, max_len=300))

    def finding(self, key: str, severity: str, title: str, asset: str) -> None:
        self.scan.emit(
            "finding",
            chakra=shuddhi.sanitize(key, max_len=40),
            severity=severity,
            title=shuddhi.sanitize(title, max_len=240),
            asset=shuddhi.sanitize(asset, max_len=240),
        )


class ScanRegistry:
    """Tracks scans, caps concurrency, and expires old ones."""

    def __init__(self) -> None:
        self._scans: dict[str, Scan] = {}
        self._lock = threading.Lock()

    def running_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._scans.values() if s.state in ("queued", "running"))

    def add(self, scan: Scan) -> None:
        with self._lock:
            self._scans[scan.id] = scan
        self._expire()

    def get(self, scan_id: str) -> Scan | None:
        with self._lock:
            return self._scans.get(scan_id)

    def _expire(self) -> None:
        cutoff = time.time() - SCAN_RETENTION
        with self._lock:
            stale = [
                sid for sid, s in self._scans.items()
                if s.finished and s.finished < cutoff
            ]
            for sid in stale:
                del self._scans[sid]


REGISTRY = ScanRegistry()


def run_scan_thread(scan: Scan) -> None:
    """Execute one scan on its own event loop in its own thread."""
    sink = SSESink(scan)
    scan.state = "running"
    scan.emit("start", target=scan.cfg.domain, chakras=scan.cfg.active_chakras(),
              config=scan.cfg.to_dict())

    try:
        result = asyncio.run(
            run_scan(scan.cfg, progress=sink, cancelled=lambda: scan.cancelled)
        )
        scan.result = result

        try:
            scan.reports = write_all(result, REPORT_DIR, scan.cfg.formats)
        except OSError as exc:
            scan.emit("note", key="dorks", text=f"report not written: {exc}")

        scan.state = "cancelled" if scan.cancelled else "done"
        scan.emit(
            "done",
            state=scan.state,
            summary=summarise(result),
            reports={fmt: os.path.basename(path) for fmt, path in scan.reports.items()},
        )
    except Exception as exc:
        scan.state = "failed"
        scan.error = f"{type(exc).__name__}: {exc}"
        scan.emit("error", message=shuddhi.sanitize(scan.error, max_len=400))
    finally:
        scan.finished = time.time()
        scan.emit("close")


def summarise(result) -> dict:
    """The payload the dashboard renders once a scan completes."""
    return {
        "target": result.target,
        "risk_score": result.risk_score,
        "risk_label": result.risk_label,
        "severity_counts": result.severity_counts(),
        "duration": round(result.duration, 1),
        "counts": {
            "findings": len(result.findings),
            "subdomains": len(result.subdomains),
            "resolved": len(result.hosts_resolved()),
            "alive": len(result.hosts_alive()),
            "open_ports": sum(
                len(v) for v in (result.infra or {}).get("open_ports", {}).values()
            ),
            "secrets": len(result.secrets),
            "endpoints": len(result.endpoints),
            "takeover": len(result.takeover),
        },
        "findings": [f.to_dict() for f in result.findings_sorted()],
        "hosts": [
            {
                "host": e.host, "status": e.status, "ips": e.ips[:3],
                "title": e.title, "tech": e.tech[:6], "ports": e.ports,
                "cname": e.cname, "url": e.url,
                "sources": sorted(e.sources),
            }
            for e in sorted(result.subdomains.values(),
                            key=lambda x: (x.status or 999, x.host))
        ],
        "takeover": result.takeover,
        "technologies": (result.infra or {}).get("technologies", {}),
        "skipped": result.skipped,
        "errors": result.errors[:30],
    }


def parse_scan_request(body: dict) -> tuple[Config | None, str]:
    """Validate a dashboard request into a Config, or return why not."""
    target = normalise_target(str(body.get("domain", "")))
    if not target or "." not in target:
        return None, "Enter a registrable domain, for example example.com."

    # The dashboard is a convenience wrapper, not a way to reach the host it
    # runs on. Loopback and the metadata address are never valid targets.
    blocked = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"}
    if target in blocked or target.endswith(".localhost") or target.endswith(".internal"):
        return None, f"'{target}' is not a valid external target."

    only = [k for k in body.get("only", []) if k in CHAKRA_KEYS]
    skip = [k for k in body.get("skip", []) if k in CHAKRA_KEYS]

    formats = [f for f in body.get("formats", ["html", "json"]) if f in FORMATS]
    if not formats:
        formats = ["html", "json"]

    ports_profile = str(body.get("ports", "top25")).lower()
    if ports_profile not in PORT_PROFILES:
        ports_profile = "top25"

    try:
        concurrency = max(1, min(200, int(body.get("concurrency", 50))))
        timeout = max(1.0, min(60.0, float(body.get("timeout", 10))))
    except (TypeError, ValueError):
        return None, "Concurrency and timeout must be numbers."

    cfg = Config(
        domain=target,
        out_dir=REPORT_DIR,
        formats=formats,
        concurrency=concurrency,
        timeout=timeout,
        only=only,
        skip=skip,
        passive_only=bool(body.get("passive_only")),
        ports_profile=ports_profile,
        deep=bool(body.get("deep")),
        quiet=True,
        plain=True,
    )
    if not cfg.active_chakras():
        return None, "No chakras selected."
    return cfg, ""


class Handler(BaseHTTPRequestHandler):
    server_version = "ChakraView/2.0"
    protocol_version = "HTTP/1.1"

    # ── helpers ───────────────────────────────────────────────────────────

    def log_message(self, fmt: str, *args) -> None:
        # One tidy line per request instead of the stdlib's noisy default.
        print(f"  {self.command:<5} {shuddhi.sanitize(self.path, max_len=120)} "
              f"— {fmt % args}")

    def _headers(self, status: int, ctype: str, length: int | None = None,
                 extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if length is not None:
            self.send_header("Content-Length", str(length))
        # The dashboard is local and self-contained, so the policy can be tight.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self._send_body(body)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _safe_path(self, url_path: str) -> str | None:
        """Resolve a URL path inside web/ only. Blocks traversal."""
        relative = unquote(url_path).lstrip("/")
        if not relative:
            relative = "index.html"
        candidate = os.path.normpath(os.path.join(WEB_DIR, relative))
        if not candidate.startswith(WEB_DIR + os.sep) and candidate != WEB_DIR:
            return None
        if os.path.isdir(candidate):
            candidate = os.path.join(candidate, "index.html")
        return candidate if os.path.isfile(candidate) else None

    def _serve_file(self, path: str, status: int = 200) -> None:
        ctype, _ = mimetypes.guess_type(path)
        if path.endswith(".svg"):
            ctype = "image/svg+xml"
        elif path.endswith(".js"):
            ctype = "text/javascript; charset=utf-8"
        elif path.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif path.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        with open(path, "rb") as handle:
            body = handle.read()
        # Never cache. This is a local tool served off the working tree, so a
        # cached stylesheet or script means edits appear not to have happened
        # — the browser keeps serving the previous version for the lifetime of
        # the max-age. There is no bandwidth worth saving over loopback.
        self._headers(status, ctype or "application/octet-stream", len(body),
                      {"Cache-Control": "no-store, must-revalidate"})
        self._send_body(body)

    def _not_found(self) -> None:
        """Serve the themed 404 page rather than the stdlib's error text."""
        custom = os.path.join(WEB_DIR, "404.html")
        if os.path.isfile(custom):
            self._serve_file(custom, status=404)
        else:
            self._json(404, {"error": "not found"})

    # ── routes ────────────────────────────────────────────────────────────

    def do_HEAD(self) -> None:
        """Same routing as GET, headers only.

        Without this the base handler answers 501 to any HEAD, which breaks
        clients that probe a URL before fetching it.
        """
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def _send_body(self, body: bytes) -> None:
        """Write a response body unless this is a HEAD request."""
        if not getattr(self, "_head_only", False):
            self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path.startswith("/api/"):
            self._api_get(path)
            return

        resolved = self._safe_path(path)
        if resolved is None:
            self._not_found()
            return
        self._serve_file(resolved)

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/scan":
            self._start_scan()
            return

        if path.startswith("/api/stop/"):
            scan = REGISTRY.get(path.rsplit("/", 1)[-1])
            if scan is None:
                self._json(404, {"error": "unknown scan"})
                return
            scan.stop()
            self._json(200, {"ok": True, "state": "stopping"})
            return

        self._json(404, {"error": "not found"})

    def _api_get(self, path: str) -> None:
        if path == "/api/chakras":
            self._json(200, {
                "chakras": CHAKRAS,
                "port_profiles": list(PORT_PROFILES),
                "formats": list(FORMATS),
            })
            return

        if path.startswith("/api/events/"):
            self._stream_events(path.rsplit("/", 1)[-1])
            return

        if path.startswith("/api/result/"):
            scan = REGISTRY.get(path.rsplit("/", 1)[-1])
            if scan is None:
                self._json(404, {"error": "unknown scan"})
                return
            if scan.result is None:
                self._json(202, {"state": scan.state})
                return
            self._json(200, {"state": scan.state, "summary": summarise(scan.result)})
            return

        if path.startswith("/api/report/"):
            self._serve_report(path[len("/api/report/"):])
            return

        self._json(404, {"error": "not found"})

    def _start_scan(self) -> None:
        body = self._read_json()
        if body is None:
            self._json(400, {"error": "Expected a JSON body."})
            return

        if REGISTRY.running_count() >= MAX_CONCURRENT_SCANS:
            self._json(429, {
                "error": f"{MAX_CONCURRENT_SCANS} scans are already running. "
                         "Wait for one to finish."
            })
            return

        cfg, error = parse_scan_request(body)
        if cfg is None:
            self._json(400, {"error": error})
            return

        scan = Scan(uuid.uuid4().hex[:16], cfg)
        REGISTRY.add(scan)
        threading.Thread(target=run_scan_thread, args=(scan,), daemon=True).start()
        self._json(202, {
            "id": scan.id,
            "target": cfg.domain,
            "chakras": cfg.active_chakras(),
        })

    def _stream_events(self, scan_id: str) -> None:
        scan = REGISTRY.get(scan_id)
        if scan is None:
            self._json(404, {"error": "unknown scan"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        last_ping = time.time()
        try:
            while True:
                try:
                    payload = scan.events.get(timeout=1.0)
                except queue.Empty:
                    # Comment frames keep the connection from idling out.
                    if time.time() - last_ping > 12:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        last_ping = time.time()
                    if scan.finished and scan.events.empty():
                        break
                    continue

                data = json.dumps(payload, ensure_ascii=False, default=str)
                self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                self.wfile.flush()
                last_ping = time.time()
                if payload.get("event") == "close":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass  # the browser navigated away

    def _serve_report(self, name: str) -> None:
        """Serve a generated report by filename, from the report directory only."""
        safe = os.path.basename(unquote(name))
        if not safe.startswith("chakraview_") or not safe.endswith(tuple(FORMATS)):
            self._not_found()
            return
        path = os.path.normpath(os.path.join(REPORT_DIR, safe))
        if not path.startswith(os.path.abspath(REPORT_DIR)) or not os.path.isfile(path):
            self._not_found()
            return

        ctype = {
            "html": "text/html; charset=utf-8",
            "json": "application/json; charset=utf-8",
            "md": "text/markdown; charset=utf-8",
            "txt": "text/plain; charset=utf-8",
        }.get(safe.rsplit(".", 1)[-1], "application/octet-stream")

        with open(path, "rb") as handle:
            body = handle.read()
        self._headers(200, ctype, len(body), {
            "Content-Disposition": f'attachment; filename="{safe}"',
            "Cache-Control": "no-store",
        })
        self._send_body(body)


def serve(host: str = "127.0.0.1", port: int = 8787) -> int:
    if not os.path.isdir(WEB_DIR):
        print(f"\nchakraview: web directory missing at {WEB_DIR}\n")
        return 1

    os.makedirs(REPORT_DIR, exist_ok=True)

    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"\nchakraview: cannot bind {host}:{port} — {exc}\n")
        return 1

    local = host in ("127.0.0.1", "localhost", "::1")
    print()
    print("  ☸  ChakraView dashboard")
    print(f"     Landing page   http://{host}:{port}/")
    print(f"     Dashboard      http://{host}:{port}/dashboard.html")
    print(f"     Reports        {REPORT_DIR}")
    if not local:
        print()
        print("  !  Bound to a non-loopback address. Anyone who can reach this")
        print("     port can start scans against arbitrary hosts through it.")
        print("     Put it behind authentication or bind 127.0.0.1 instead.")
    print()
    print("     Ctrl-C to stop.")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down.\n")
    finally:
        httpd.server_close()
    return 0
