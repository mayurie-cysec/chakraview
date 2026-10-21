"""SQLite storage for users, sessions and scan history.

SQLite rather than a server database because ChakraView is a tool people
clone and run: a dependency on Postgres would stop most of them before they
start. It is also deliberately *not* kept on a synced cloud drive — a sync
client does not honour SQLite's file locking, so two writers corrupt the file
rather than queueing, and session tokens and TOTP secrets have no business
sitting in third-party storage.

Every connection runs in WAL mode so a scan thread can write events while a
request thread reads them. Connections are per-thread, because a SQLite
connection is not safe to share across threads.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any, Iterable

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chakraview.db"
)

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   BLOB    NOT NULL,
    password_salt   BLOB    NOT NULL,
    -- Cost parameters are stored per row so an existing user's hash stays
    -- verifiable after the defaults are raised.
    kdf_n           INTEGER NOT NULL,
    kdf_r           INTEGER NOT NULL,
    kdf_p           INTEGER NOT NULL,
    totp_secret     TEXT,
    totp_confirmed  INTEGER NOT NULL DEFAULT 0,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      REAL    NOT NULL,
    last_login_at   REAL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL    NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    -- The primary key is a hash of the cookie value, never the value itself:
    -- a stolen database must not yield usable session cookies.
    token_hash   TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    expires_at   REAL    NOT NULL,
    last_seen_at REAL    NOT NULL,
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

-- One row per accepted TOTP step, so a code cannot be replayed inside its
-- own validity window by anyone who observes it.
CREATE TABLE IF NOT EXISTS totp_used (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    counter INTEGER NOT NULL,
    used_at REAL    NOT NULL,
    PRIMARY KEY (user_id, counter)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    ip       TEXT NOT NULL,
    username TEXT,
    ts       REAL NOT NULL,
    ok       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip, ts);

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target      TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    config_json TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    started_at  REAL,
    finished_at REAL,
    risk_score  INTEGER,
    risk_label  TEXT,
    counts_json TEXT,
    error       TEXT,
    last_seq    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- The live event stream, kept so a browser that reloads or navigates away can
-- replay what it missed instead of losing the scan.
CREATE TABLE IF NOT EXISTS scan_events (
    scan_id TEXT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    ts      REAL    NOT NULL,
    payload TEXT    NOT NULL,
    PRIMARY KEY (scan_id, seq)
);

CREATE TABLE IF NOT EXISTS scan_results (
    scan_id      TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    summary_json TEXT NOT NULL,
    reports_json TEXT NOT NULL
);
"""


class Database:
    """Thread-local SQLite connections against one file."""

    def __init__(self, path: str = "") -> None:
        self.path = os.path.abspath(path or DEFAULT_PATH)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._initialised = False
        self.init()

    # ── connection ────────────────────────────────────────────────────────

    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        fresh = not os.path.exists(self.path)
        conn = sqlite3.connect(self.path, timeout=20.0, isolation_level=None)
        if fresh:
            # The file holds session material and TOTP secrets.
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=20000")
        self._local.conn = conn
        return conn

    def init(self) -> None:
        with self._init_lock:
            if self._initialised:
                return
            conn = self.connect()
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._initialised = True

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ── helpers ───────────────────────────────────────────────────────────

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self.connect().execute(sql, tuple(params))

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        return self.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Iterable[Any] = (), default: Any = None) -> Any:
        row = self.one(sql, params)
        return row[0] if row is not None else default

    # ── maintenance ───────────────────────────────────────────────────────

    def purge_expired(self) -> None:
        """Drop anything that has aged out. Cheap enough to run on a timer."""
        now = time.time()
        conn = self.connect()
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM login_attempts WHERE ts < ?", (now - 86400,))
        conn.execute("DELETE FROM totp_used WHERE used_at < ?", (now - 3600,))

    def mark_interrupted_scans(self) -> int:
        """Scans still marked running at startup died with the last process.

        A scan runs in a thread; nothing survives a restart. Leaving rows in
        'running' would show the user a scan that will never emit another
        event, so they are closed out honestly instead.
        """
        cur = self.execute(
            "UPDATE scans SET status='interrupted', finished_at=?, "
            "error='Server restarted while this scan was running' "
            "WHERE status IN ('queued','running')",
            (time.time(),),
        )
        return cur.rowcount or 0
