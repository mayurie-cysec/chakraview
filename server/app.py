"""Local web server: authentication, scan execution and scan history.

Standard library only. A reconnaissance tool people clone and run should not
need a web framework installed before its dashboard will open.

Three things shape the design:

* **A scan belongs to the server, not to a browser tab.** It runs on a worker
  thread and every progress event is written to the database with a sequence
  number. Reloading the page, navigating away, or losing the connection costs
  nothing: the client reports the last sequence it saw and is replayed from
  storage before the live stream resumes.
* **Nothing from the client is trusted.** Identity comes from a server-side
  session, never from a request body. Scan ownership is enforced in SQL on
  every read. Every scan option is re-validated here regardless of what the
  form sent.
* **The dashboard starts network scans**, so whoever reaches this port can
  scan arbitrary hosts through it. It binds to loopback, requires a login
  with a second factor, and says so loudly when bound wider.
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
from http import cookies as http_cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from core.auth import (SESSION_COOKIE, Auth, AuthError, constant_time_eq,
                       password_problem, recovery_codes, totp_uri)
from core.context import CHAKRA_KEYS, CHAKRAS, PORT_PROFILES, Config, ProgressSink
from core.db import Database
from core.engine import normalise_target, run_scan
from core.report import FORMATS, write_all
from core.store import (ACTIVE_STATUSES, ALL_STATUSES, STATUS_CANCELLED,
                        STATUS_COMPLETED, STATUS_FAILED, STATUS_RUNNING,
                        ScanStore)
from modules import shuddhi

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(ROOT, "web")
REPORT_DIR = os.path.join(ROOT, "reports")

MAX_BODY = 64 * 1024
MAX_CONCURRENT_SCANS = 2
MAX_SCANS_PER_USER = 1

# Served without a session. Everything else needs one.
PUBLIC_PATHS = {"/login.html", "/api/auth/login", "/api/auth/totp",
                "/api/auth/status", "/404.html"}
PUBLIC_PREFIXES = ("/assets/",)

DB: Database
AUTH: Auth
STORE: ScanStore


# ══════════════════════════════════════════════════════════════════════════
# Live scan state
# ══════════════════════════════════════════════════════════════════════════

class Scan:
    """In-memory handle for a running scan.

    The database holds the durable record; this exists so live subscribers
    get events without polling. Several tabs can watch one scan, so events
    fan out to every subscriber rather than being consumed from a single
    queue by whoever reads first.
    """

    def __init__(self, scan_id: str, user_id: int, cfg: Config) -> None:
        self.id = scan_id
        self.user_id = user_id
        self.cfg = cfg
        self.status = "queued"
        self.finished = False
        self._stop = threading.Event()
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def emit(self, kind: str, **payload) -> None:
        payload["event"] = kind
        seq = STORE.append_event(self.id, payload)
        payload["seq"] = seq
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(payload)
            except queue.Full:
                # A stalled reader must not stall the scan. It can catch up
                # from the database when it reconnects.
                pass

    def stop(self) -> None:
        self._stop.set()

    @property
    def cancelled(self) -> bool:
        return self._stop.is_set()


class SSESink(ProgressSink):
    """Turns module progress callbacks into stored, streamed events."""

    def __init__(self, scan: Scan) -> None:
        self.scan = scan
        self._totals: dict[str, int] = {}
        self._done: dict[str, int] = {}

    def chakra_start(self, key: str) -> None:
        self.scan.emit("chakra_start", key=key)

    def chakra_done(self, key: str, summary: str = "") -> None:
        self.scan.emit("chakra_done", key=key,
                       summary=shuddhi.sanitize(summary, max_len=300))

    def chakra_elapsed(self, key: str, seconds: float) -> None:
        self.scan.emit("chakra_elapsed", key=key, seconds=round(seconds, 1))

    def chakra_skip(self, key: str, reason: str) -> None:
        self.scan.emit("chakra_skip", key=key,
                       reason=shuddhi.sanitize(reason, max_len=120))

    def task(self, key: str, label: str, total: int | None = None) -> None:
        self._totals[key] = total or 0
        self._done[key] = 0
        self.scan.emit("task", key=key, label=shuddhi.sanitize(label, max_len=160),
                       total=total or 0)

    def advance(self, key: str, amount: int = 1) -> None:
        self._done[key] = self._done.get(key, 0) + amount
        total = self._totals.get(key, 0)
        # Coalesce: a 50k-candidate bruteforce must not write 50k rows.
        step = max(1, total // 100) if total else 25
        if self._done[key] % step == 0 or (total and self._done[key] >= total):
            self.scan.emit("advance", key=key, done=self._done[key], total=total)

    def hit(self, key: str, text: str) -> None:
        self.scan.emit("hit", key=key, text=shuddhi.sanitize(text, max_len=300))

    def note(self, key: str, text: str) -> None:
        self.scan.emit("note", key=key, text=shuddhi.sanitize(text, max_len=300))

    def finding(self, key: str, severity: str, title: str, asset: str) -> None:
        self.scan.emit("finding", chakra=shuddhi.sanitize(key, max_len=40),
                       severity=severity,
                       title=shuddhi.sanitize(title, max_len=240),
                       asset=shuddhi.sanitize(asset, max_len=240))


class Registry:
    """Live scans only. History comes from the database."""

    def __init__(self) -> None:
        self._scans: dict[str, Scan] = {}
        self._lock = threading.Lock()

    def add(self, scan: Scan) -> None:
        with self._lock:
            self._scans[scan.id] = scan

    def get(self, scan_id: str) -> Scan | None:
        with self._lock:
            return self._scans.get(scan_id)

    def running_total(self) -> int:
        with self._lock:
            return sum(1 for s in self._scans.values() if not s.finished)

    def running_for_user(self, user_id: int) -> int:
        with self._lock:
            return sum(1 for s in self._scans.values()
                       if not s.finished and s.user_id == user_id)

    def retire(self, scan_id: str) -> None:
        with self._lock:
            scan = self._scans.get(scan_id)
            if scan:
                scan.finished = True

    def sweep(self) -> None:
        """Drop finished scans nothing is watching any more."""
        with self._lock:
            for sid in [s.id for s in self._scans.values()
                        if s.finished and not s._subscribers]:
                self._scans.pop(sid, None)


REGISTRY = Registry()


def summarise(result) -> dict:
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
            "open_ports": sum(len(v) for v in
                              (result.infra or {}).get("open_ports", {}).values()),
            "secrets": len(result.secrets),
            "endpoints": len(result.endpoints),
            "takeover": len(result.takeover),
        },
        "findings": [f.to_dict() for f in result.findings_sorted()],
        "hosts": [
            {"host": e.host, "status": e.status, "ips": e.ips[:3], "title": e.title,
             "tech": e.tech[:6], "ports": e.ports, "cname": e.cname, "url": e.url,
             "sources": sorted(e.sources)}
            for e in sorted(result.subdomains.values(),
                            key=lambda x: (x.status or 999, x.host))
        ],
        "takeover": result.takeover,
        "technologies": (result.infra or {}).get("technologies", {}),
        "skipped": result.skipped,
        "errors": result.errors[:30],
    }


def run_scan_thread(scan: Scan) -> None:
    sink = SSESink(scan)
    scan.status = STATUS_RUNNING
    STORE.set_status(scan.id, STATUS_RUNNING)
    scan.emit("start", target=scan.cfg.domain, chakras=scan.cfg.active_chakras(),
              config=scan.cfg.to_dict())

    try:
        result = asyncio.run(
            run_scan(scan.cfg, progress=sink, cancelled=lambda: scan.cancelled))

        reports: dict[str, str] = {}
        try:
            reports = write_all(result, REPORT_DIR, scan.cfg.formats)
        except OSError as exc:
            scan.emit("note", key="dorks", text=f"report not written: {exc}")

        summary = summarise(result)
        names = {fmt: os.path.basename(path) for fmt, path in reports.items()}
        STORE.save_result(scan.id, summary, names)

        status = STATUS_CANCELLED if scan.cancelled else STATUS_COMPLETED
        scan.status = status
        STORE.set_status(scan.id, status)
        scan.emit("done", state=status, summary=summary, reports=names)
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        scan.status = STATUS_FAILED
        STORE.set_status(scan.id, STATUS_FAILED, error=message)
        scan.emit("error", message=shuddhi.sanitize(message, max_len=400))
    finally:
        scan.emit("close")
        REGISTRY.retire(scan.id)
        DB.close()


def parse_scan_request(body: dict) -> tuple[Config | None, str]:
    """Validate a dashboard request into a Config, or return why not.

    Called on every submission regardless of what the form enforces. The
    browser is a convenience, not a gate.
    """
    target = normalise_target(str(body.get("domain", "")))
    if not target or "." not in target:
        return None, "Enter a registrable domain, for example example.com."

    blocked = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"}
    if target in blocked or target.endswith((".localhost", ".internal", ".local")):
        return None, f"'{target}' is not a valid external target."

    only = [k for k in body.get("only", []) if k in CHAKRA_KEYS]
    skip = [k for k in body.get("skip", []) if k in CHAKRA_KEYS]
    formats = [f for f in body.get("formats", ["html", "json"]) if f in FORMATS] \
        or ["html", "json"]
    ports_profile = str(body.get("ports", "top25")).lower()
    if ports_profile not in PORT_PROFILES:
        ports_profile = "top25"

    try:
        concurrency = max(1, min(200, int(body.get("concurrency", 50))))
        timeout = max(1.0, min(60.0, float(body.get("timeout", 10))))
    except (TypeError, ValueError):
        return None, "Concurrency and timeout must be numbers."

    cfg = Config(domain=target, out_dir=REPORT_DIR, formats=formats,
                 concurrency=concurrency, timeout=timeout, only=only, skip=skip,
                 passive_only=bool(body.get("passive_only")),
                 ports_profile=ports_profile, deep=bool(body.get("deep")),
                 quiet=True, plain=True)
    if not cfg.active_chakras():
        return None, "No chakras selected."
    return cfg, ""


# ══════════════════════════════════════════════════════════════════════════
# HTTP
# ══════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    server_version = "ChakraView/2.0"
    protocol_version = "HTTP/1.1"

    # ── plumbing ──────────────────────────────────────────────────────────

    def log_message(self, fmt: str, *args) -> None:
        print(f"  {self.command:<5} {shuddhi.sanitize(self.path, max_len=110)} "
              f"— {fmt % args}")

    @property
    def client_ip(self) -> str:
        # No proxy headers are honoured. This binds to loopback by default,
        # and trusting X-Forwarded-For without a known proxy in front lets a
        # client forge its own address past the rate limiter.
        return (self.client_address[0] if self.client_address else "?")[:64]

    def _headers(self, status: int, ctype: str, length: int | None = None,
                 extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy",
                         "geolocation=(), microphone=(), camera=(), payment=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'")
        # Never cache: this is served off the working tree, and responses are
        # per-user.
        self.send_header("Cache-Control", "no-store, must-revalidate, private")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _send_body(self, body: bytes) -> None:
        if not getattr(self, "_head_only", False):
            self.wfile.write(body)

    def _json(self, status: int, payload: dict, extra: dict | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body), extra)
        self._send_body(body)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _redirect(self, location: str) -> None:
        self._headers(302, "text/html; charset=utf-8", 0, {"Location": location})

    # ── session ───────────────────────────────────────────────────────────

    def _cookie_token(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        jar = http_cookies.SimpleCookie()
        try:
            jar.load(raw)
        except http_cookies.CookieError:
            return ""
        morsel = jar.get(SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _set_session_cookie(self, token: str, max_age: int) -> str:
        # HttpOnly keeps it away from script; SameSite=Strict means a cross-site
        # request never carries it, which is the backstop behind the CSRF token.
        parts = [f"{SESSION_COOKIE}={token}", "Path=/", "HttpOnly",
                 "SameSite=Strict", f"Max-Age={max_age}"]
        if self.headers.get("X-Forwarded-Proto") == "https":
            parts.append("Secure")
        return "; ".join(parts)

    def _session(self):
        return AUTH.load_session(self._cookie_token())

    def _origin_ok(self) -> bool:
        """Reject a cross-origin write even before the CSRF token is checked."""
        origin = self.headers.get("Origin") or ""
        if not origin:
            referer = self.headers.get("Referer") or ""
            if not referer:
                # A same-origin fetch may legitimately send neither header.
                # SameSite=Strict on the session cookie covers this case.
                return True
            parts = urlparse(referer)
            origin = f"{parts.scheme}://{parts.netloc}"
        host = self.headers.get("Host") or ""
        return bool(host) and origin.endswith(f"//{host}")

    def _require_session(self, api: bool = True):
        session = self._session()
        if session is None:
            if api:
                self._json(401, {"error": "Not signed in.", "auth": "required"})
            else:
                self._redirect("/login.html")
            return None
        return session

    def _csrf_ok(self, session) -> bool:
        return constant_time_eq(self.headers.get("X-CSRF-Token", ""),
                                session.csrf_token)

    def _require_write(self):
        """Session plus CSRF plus origin, for anything that changes state."""
        session = self._require_session()
        if session is None:
            return None
        if not self._origin_ok():
            self._json(403, {"error": "Cross-origin request refused."})
            return None
        if not self._csrf_ok(session):
            self._json(403, {"error": "Invalid or missing CSRF token."})
            return None
        return session

    # ── static ────────────────────────────────────────────────────────────

    def _safe_path(self, url_path: str) -> str | None:
        relative = unquote(url_path).lstrip("/") or "index.html"
        candidate = os.path.normpath(os.path.join(WEB_DIR, relative))
        if not candidate.startswith(WEB_DIR + os.sep) and candidate != WEB_DIR:
            return None
        if os.path.isdir(candidate):
            candidate = os.path.join(candidate, "index.html")
        return candidate if os.path.isfile(candidate) else None

    def _serve_file(self, path: str, status: int = 200) -> None:
        ctype = {".svg": "image/svg+xml", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8",
                 ".html": "text/html; charset=utf-8"}.get(
            os.path.splitext(path)[1], mimetypes.guess_type(path)[0]
            or "application/octet-stream")
        with open(path, "rb") as handle:
            body = handle.read()
        self._headers(status, ctype, len(body))
        self._send_body(body)

    def _not_found(self) -> None:
        custom = os.path.join(WEB_DIR, "404.html")
        if os.path.isfile(custom):
            self._serve_file(custom, status=404)
        else:
            self._json(404, {"error": "not found"})

    # ── routing ───────────────────────────────────────────────────────────

    def do_HEAD(self) -> None:
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, params = parsed.path, parse_qs(parsed.query)

        if path.startswith("/api/"):
            self._api_get(path, params)
            return

        # Pages other than the login screen need a session.
        if path not in PUBLIC_PATHS and not path.startswith(PUBLIC_PREFIXES):
            if path.endswith(".html") or path in ("/", ""):
                if self._session() is None:
                    self._redirect("/login.html")
                    return

        # A signed-in user landing on the login page goes to the dashboard.
        if path == "/login.html" and self._session() is not None:
            self._redirect("/dashboard.html")
            return

        resolved = self._safe_path(path)
        if resolved is None:
            self._not_found()
            return
        self._serve_file(resolved)

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/auth/login":
            self._login()
        elif path == "/api/auth/totp":
            self._totp()
        elif path == "/api/auth/logout":
            self._logout()
        elif path == "/api/scan":
            self._start_scan()
        elif path.startswith("/api/scan/") and path.endswith("/stop"):
            self._stop_scan(path.split("/")[3])
        else:
            self._json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/scan/"):
            self._delete_scan(path.split("/")[3])
        else:
            self._json(404, {"error": "not found"})

    # ── auth endpoints ────────────────────────────────────────────────────

    def _login(self) -> None:
        if not self._origin_ok():
            self._json(403, {"error": "Cross-origin request refused."})
            return
        body = self._read_json()
        if body is None:
            self._json(400, {"error": "Expected a JSON body."})
            return
        try:
            outcome = AUTH.begin_login(str(body.get("username", "")),
                                       str(body.get("password", "")),
                                       self.client_ip)
        except AuthError as exc:
            extra = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
            self._json(exc.status, {"error": exc.message}, extra)
            return

        if outcome["stage"] == "totp":
            self._json(200, {"stage": "totp", "challenge": outcome["challenge"],
                             "enrol": outcome["enrol"]})
            return
        self._issue_session(outcome)

    def _totp(self) -> None:
        if not self._origin_ok():
            self._json(403, {"error": "Cross-origin request refused."})
            return
        body = self._read_json()
        if body is None:
            self._json(400, {"error": "Expected a JSON body."})
            return
        try:
            outcome = AUTH.complete_login(str(body.get("challenge", "")),
                                          str(body.get("code", "")),
                                          self.client_ip)
        except AuthError as exc:
            extra = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
            self._json(exc.status, {"error": exc.message}, extra)
            return
        self._issue_session(outcome)

    def _issue_session(self, outcome: dict) -> None:
        from core.auth import SESSION_TTL

        token, session = AUTH.start_session(
            outcome["user_id"], self.client_ip,
            self.headers.get("User-Agent", ""))
        self._json(200, {
            "stage": "done",
            "user": {"username": session.username, "is_admin": session.is_admin},
            # The CSRF token goes in the body, not a cookie: a reader has to
            # be able to run script on this origin to get it.
            "csrf": session.csrf_token,
        }, {"Set-Cookie": self._set_session_cookie(token, SESSION_TTL)})

    def _logout(self) -> None:
        session = self._session()
        if session is not None and self._csrf_ok(session):
            AUTH.end_session(self._cookie_token())
        self._json(200, {"ok": True}, {
            "Set-Cookie": f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        })

    # ── scans ─────────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        session = self._require_write()
        if session is None:
            return

        if REGISTRY.running_total() >= MAX_CONCURRENT_SCANS:
            self._json(429, {"error": f"{MAX_CONCURRENT_SCANS} scans are already "
                                      "running on this server. Wait for one to finish."})
            return
        if REGISTRY.running_for_user(session.user_id) >= MAX_SCANS_PER_USER:
            self._json(429, {"error": "You already have a scan running. "
                                      "Stop it or wait for it to finish."})
            return

        body = self._read_json()
        if body is None:
            self._json(400, {"error": "Expected a JSON body."})
            return
        cfg, error = parse_scan_request(body)
        if cfg is None:
            self._json(400, {"error": error})
            return

        scan_id = uuid.uuid4().hex[:16]
        # Recorded before the thread starts, so a crash between the two still
        # leaves a row the user can see rather than a scan that never existed.
        STORE.create(scan_id, session.user_id, cfg.domain, cfg.to_dict())
        scan = Scan(scan_id, session.user_id, cfg)
        REGISTRY.add(scan)
        threading.Thread(target=run_scan_thread, args=(scan,), daemon=True).start()

        self._json(202, {"id": scan_id, "target": cfg.domain,
                         "chakras": cfg.active_chakras(), "status": "queued"})

    def _stop_scan(self, scan_id: str) -> None:
        session = self._require_write()
        if session is None:
            return
        row = STORE.get(scan_id, session.user_id, session.is_admin)
        if row is None:
            self._json(404, {"error": "No such scan."})
            return
        scan = REGISTRY.get(scan_id)
        if scan is not None:
            scan.stop()
        self._json(200, {"ok": True, "status": "stopping"})

    def _delete_scan(self, scan_id: str) -> None:
        session = self._require_write()
        if session is None:
            return
        row = STORE.get(scan_id, session.user_id, session.is_admin)
        if row is None:
            self._json(404, {"error": "No such scan."})
            return
        if row["status"] in ACTIVE_STATUSES:
            self._json(409, {"error": "Stop the scan before deleting it."})
            return
        STORE.delete(scan_id, session.user_id, session.is_admin)
        self._json(200, {"ok": True})

    # ── reads ─────────────────────────────────────────────────────────────

    def _api_get(self, path: str, params: dict) -> None:
        # Status is public so the login page can tell whether a server has
        # been set up yet. It discloses nothing about any individual user.
        if path == "/api/auth/status":
            session = self._session()
            self._json(200, {
                "authenticated": session is not None,
                "user": ({"username": session.username, "is_admin": session.is_admin}
                         if session else None),
                "csrf": session.csrf_token if session else None,
                "setup_required": AUTH.user_count() == 0,
            })
            return

        session = self._require_session()
        if session is None:
            return

        if path == "/api/chakras":
            self._json(200, {"chakras": CHAKRAS, "port_profiles": list(PORT_PROFILES),
                             "formats": list(FORMATS), "statuses": list(ALL_STATUSES)})
            return

        if path == "/api/history":
            try:
                limit = int(params.get("limit", ["50"])[0])
                offset = int(params.get("offset", ["0"])[0])
            except ValueError:
                limit, offset = 50, 0
            status = params.get("status", [""])[0]
            self._json(200, {
                "scans": STORE.history(session.user_id, session.is_admin,
                                       limit=limit, offset=offset, status=status),
                "total": STORE.count(session.user_id, session.is_admin),
                "active": STORE.active_for_user(session.user_id),
            })
            return

        if path.startswith("/api/events/"):
            self._stream_events(path.rsplit("/", 1)[-1], params, session)
            return

        if path.startswith("/api/scan/"):
            self._scan_detail(path.split("/")[3], session)
            return

        if path.startswith("/api/report/"):
            self._serve_report(path[len("/api/report/"):], session)
            return

        self._json(404, {"error": "not found"})

    def _scan_detail(self, scan_id: str, session) -> None:
        row = STORE.get(scan_id, session.user_id, session.is_admin)
        if row is None:
            self._json(404, {"error": "No such scan."})
            return
        record = STORE._row_to_dict(row)
        stored = STORE.result(scan_id)
        self._json(200, {
            "scan": record,
            "summary": (stored or {}).get("summary"),
            "reports": (stored or {}).get("reports", {}),
            "live": REGISTRY.get(scan_id) is not None and row["status"] in ACTIVE_STATUSES,
        })

    def _stream_events(self, scan_id: str, params: dict, session) -> None:
        """Replay what the client missed, then follow the live stream.

        This is what makes a reload free. The client sends the last sequence
        number it saw, is caught up from storage, and only then attaches to
        the running scan.
        """
        row = STORE.get(scan_id, session.user_id, session.is_admin)
        if row is None:
            self._json(404, {"error": "No such scan."})
            return

        try:
            after = int(params.get("after", ["0"])[0])
        except ValueError:
            after = 0
        last_event_id = self.headers.get("Last-Event-ID")
        if last_event_id and last_event_id.isdigit():
            after = max(after, int(last_event_id))

        scan = REGISTRY.get(scan_id)
        subscription = scan.subscribe() if scan is not None else None

        # An event stream carries no Content-Length, so under HTTP/1.1 the
        # only thing that delimits it is closing the connection. Without
        # this the client keeps reading after the final event and hangs.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def write(payload: dict, seq: int) -> None:
            data = json.dumps(payload, ensure_ascii=False, default=str)
            self.wfile.write(f"id: {seq}\ndata: {data}\n\n".encode("utf-8"))
            self.wfile.flush()

        try:
            replayed = 0
            for seq, payload in STORE.events_since(scan_id, after):
                payload["seq"] = seq
                payload["replay"] = True
                write(payload, seq)
                replayed = seq

            if row["status"] not in ACTIVE_STATUSES:
                write({"event": "close", "state": row["status"]}, replayed + 1)
                return
            if subscription is None:
                # Marked active but no live handle: the process restarted.
                write({"event": "error",
                       "message": "This scan did not survive a server restart."},
                      replayed + 1)
                write({"event": "close", "state": "interrupted"}, replayed + 2)
                return

            last_ping = time.time()
            while True:
                try:
                    payload = subscription.get(timeout=1.0)
                except queue.Empty:
                    if time.time() - last_ping > 12:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        last_ping = time.time()
                    continue
                seq = payload.get("seq", 0)
                if seq <= replayed:
                    continue        # already sent during replay
                write(payload, seq)
                replayed = seq
                last_ping = time.time()
                if payload.get("event") == "close":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if scan is not None and subscription is not None:
                scan.unsubscribe(subscription)
            REGISTRY.sweep()

    def _serve_report(self, name: str, session) -> None:
        safe = os.path.basename(unquote(name))
        if not safe.startswith("chakraview_") or not safe.endswith(tuple(FORMATS)):
            self._not_found()
            return

        # A report is only downloadable through a scan the caller owns.
        # Filenames are guessable; ownership is not.
        owned = False
        for record in STORE.history(session.user_id, session.is_admin, limit=500):
            stored = STORE.result(record["id"])
            if stored and safe in (stored.get("reports") or {}).values():
                owned = True
                break
        if not owned:
            self._not_found()
            return

        path = os.path.normpath(os.path.join(REPORT_DIR, safe))
        if not path.startswith(os.path.abspath(REPORT_DIR)) or not os.path.isfile(path):
            self._not_found()
            return

        ctype = {"html": "text/html; charset=utf-8",
                 "json": "application/json; charset=utf-8",
                 "md": "text/markdown; charset=utf-8",
                 "txt": "text/plain; charset=utf-8"}.get(
            safe.rsplit(".", 1)[-1], "application/octet-stream")
        with open(path, "rb") as handle:
            body = handle.read()
        self._headers(200, ctype, len(body),
                      {"Content-Disposition": f'attachment; filename="{safe}"'})
        self._send_body(body)


def serve(host: str = "127.0.0.1", port: int = 8787, db_path: str = "") -> int:
    global DB, AUTH, STORE

    if not os.path.isdir(WEB_DIR):
        print(f"\nchakraview: web directory missing at {WEB_DIR}\n")
        return 1
    os.makedirs(REPORT_DIR, exist_ok=True)

    DB = Database(db_path)
    AUTH = Auth(DB)
    STORE = ScanStore(DB)
    DB.purge_expired()
    stranded = DB.mark_interrupted_scans()

    if AUTH.user_count() == 0:
        print("\n  No users exist yet. Create one before starting the server:\n")
        print("      python3 chakraview.py --create-user <name> --admin\n")
        return 1

    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"\nchakraview: cannot bind {host}:{port} — {exc}\n")
        return 1

    local = host in ("127.0.0.1", "localhost", "::1")
    print()
    print("  ☸  ChakraView")
    print(f"     Sign in     http://{host}:{port}/login.html")
    print(f"     Dashboard   http://{host}:{port}/dashboard.html")
    print(f"     History     http://{host}:{port}/history.html")
    print(f"     Database    {DB.path}")
    print(f"     Reports     {REPORT_DIR}")
    if stranded:
        print(f"\n  {stranded} scan(s) were still marked running from a previous "
              "process and have been closed as interrupted.")
    if not local:
        print()
        print("  !  Bound to a non-loopback address. Every account on this server")
        print("     can scan arbitrary hosts through it. Put TLS and a reverse")
        print("     proxy in front, or bind 127.0.0.1 instead.")
    print("\n     Ctrl-C to stop.\n")

    def janitor() -> None:
        while True:
            time.sleep(300)
            try:
                DB.purge_expired()
                REGISTRY.sweep()
            except Exception:
                pass

    threading.Thread(target=janitor, daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down.\n")
    finally:
        httpd.server_close()
    return 0
