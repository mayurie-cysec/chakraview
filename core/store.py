"""Scan persistence: history, live events, and results.

The point of this module is that a scan belongs to the server, not to a
browser tab. Every progress event is written here with a monotonic sequence
number, so a client that reloads, navigates away, or loses its connection can
say "I last saw event 412" and be caught up from the database before the live
stream resumes. Closing the tab does not touch the scan.

Ownership is enforced on every read. A scan id is a random token, but the
queries still filter by user_id so guessing one would not be enough.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

# Lifecycle. `queued` is what the UI shows as pending or initiated; the rest
# are terminal except `running`.
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_INTERRUPTED = "interrupted"

ACTIVE_STATUSES = (STATUS_QUEUED, STATUS_RUNNING)
TERMINAL_STATUSES = (STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED,
                     STATUS_INTERRUPTED)
ALL_STATUSES = ACTIVE_STATUSES + TERMINAL_STATUSES

# How much of the event stream to keep per scan. Enough to rebuild the live
# view after a reload; the full detail lives in the saved report.
MAX_EVENTS_PER_SCAN = 4000


class ScanStore:
    def __init__(self, db) -> None:
        self.db = db
        # Sequence numbers are allocated in process, one lock per store, so
        # two threads writing events for different scans cannot collide on a
        # primary key.
        self._seq_lock = threading.Lock()
        self._seq: dict[str, int] = {}

    # ── lifecycle ─────────────────────────────────────────────────────────

    def create(self, scan_id: str, user_id: int, target: str, config: dict) -> None:
        self.db.execute(
            "INSERT INTO scans(id, user_id, target, status, config_json, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (scan_id, user_id, target, STATUS_QUEUED,
             json.dumps(config, default=str), time.time()))
        with self._seq_lock:
            self._seq[scan_id] = 0

    def set_status(self, scan_id: str, status: str, error: str = "") -> None:
        if status not in ALL_STATUSES:
            raise ValueError(f"unknown scan status: {status}")
        now = time.time()
        if status == STATUS_RUNNING:
            self.db.execute(
                "UPDATE scans SET status = ?, started_at = COALESCE(started_at, ?)"
                " WHERE id = ?", (status, now, scan_id))
        elif status in TERMINAL_STATUSES:
            self.db.execute(
                "UPDATE scans SET status = ?, finished_at = ?, error = ? WHERE id = ?",
                (status, now, error or None, scan_id))
        else:
            self.db.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))

    def save_result(self, scan_id: str, summary: dict, reports: dict) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO scan_results(scan_id, summary_json, reports_json)"
            " VALUES(?,?,?)",
            (scan_id, json.dumps(summary, default=str), json.dumps(reports, default=str)))
        counts = summary.get("counts", {})
        self.db.execute(
            "UPDATE scans SET risk_score = ?, risk_label = ?, counts_json = ? WHERE id = ?",
            (summary.get("risk_score"), summary.get("risk_label"),
             json.dumps(counts, default=str), scan_id))

    # ── events ────────────────────────────────────────────────────────────

    def append_event(self, scan_id: str, payload: dict) -> int:
        """Store one progress event and return its sequence number."""
        with self._seq_lock:
            if scan_id not in self._seq:
                self._seq[scan_id] = int(self.db.scalar(
                    "SELECT COALESCE(MAX(seq), 0) FROM scan_events WHERE scan_id = ?",
                    (scan_id,), default=0) or 0)
            self._seq[scan_id] += 1
            seq = self._seq[scan_id]
        try:
            self.db.execute(
                "INSERT INTO scan_events(scan_id, seq, ts, payload) VALUES(?,?,?,?)",
                (scan_id, seq, time.time(), json.dumps(payload, default=str)))
            self.db.execute("UPDATE scans SET last_seq = ? WHERE id = ?", (seq, scan_id))
        except sqlite3.Error:
            # Losing one progress line must never take the scan down with it.
            return seq
        if seq % 500 == 0:
            self._trim_events(scan_id, seq)
        return seq

    def _trim_events(self, scan_id: str, newest: int) -> None:
        self.db.execute(
            "DELETE FROM scan_events WHERE scan_id = ? AND seq <= ?",
            (scan_id, newest - MAX_EVENTS_PER_SCAN))

    def events_since(self, scan_id: str, after: int = 0,
                     limit: int = MAX_EVENTS_PER_SCAN) -> list[tuple[int, dict]]:
        rows = self.db.query(
            "SELECT seq, payload FROM scan_events WHERE scan_id = ? AND seq > ?"
            " ORDER BY seq LIMIT ?", (scan_id, after, limit))
        out: list[tuple[int, dict]] = []
        for row in rows:
            try:
                out.append((row["seq"], json.loads(row["payload"])))
            except ValueError:
                continue
        return out

    # ── reads (always scoped to an owner) ─────────────────────────────────

    def get(self, scan_id: str, user_id: int, is_admin: bool = False):
        if is_admin:
            return self.db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return self.db.one("SELECT * FROM scans WHERE id = ? AND user_id = ?",
                           (scan_id, user_id))

    def result(self, scan_id: str) -> dict[str, Any] | None:
        row = self.db.one("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
        if row is None:
            return None
        try:
            return {"summary": json.loads(row["summary_json"]),
                    "reports": json.loads(row["reports_json"])}
        except ValueError:
            return None

    def history(self, user_id: int, is_admin: bool = False, limit: int = 100,
                offset: int = 0, status: str = "") -> list[dict[str, Any]]:
        where, params = [], []
        if not is_admin:
            where.append("s.user_id = ?"); params.append(user_id)
        if status in ALL_STATUSES:
            where.append("s.status = ?"); params.append(status)
        elif status == "active":
            where.append(f"s.status IN ({','.join('?' * len(ACTIVE_STATUSES))})")
            params.extend(ACTIVE_STATUSES)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        params.extend([max(1, min(limit, 500)), max(0, offset)])

        rows = self.db.query(
            f"SELECT s.*, u.username FROM scans s JOIN users u ON u.id = s.user_id"
            f" {clause} ORDER BY s.created_at DESC LIMIT ? OFFSET ?", params)
        return [self._row_to_dict(r) for r in rows]

    def count(self, user_id: int, is_admin: bool = False) -> int:
        if is_admin:
            return int(self.db.scalar("SELECT COUNT(*) FROM scans", default=0) or 0)
        return int(self.db.scalar("SELECT COUNT(*) FROM scans WHERE user_id = ?",
                                  (user_id,), default=0) or 0)

    def active_for_user(self, user_id: int) -> list[dict[str, Any]]:
        rows = self.db.query(
            f"SELECT s.*, u.username FROM scans s JOIN users u ON u.id = s.user_id"
            f" WHERE s.user_id = ? AND s.status IN"
            f" ({','.join('?' * len(ACTIVE_STATUSES))}) ORDER BY s.created_at DESC",
            (user_id, *ACTIVE_STATUSES))
        return [self._row_to_dict(r) for r in rows]

    def delete(self, scan_id: str, user_id: int, is_admin: bool = False) -> bool:
        row = self.get(scan_id, user_id, is_admin)
        if row is None:
            return False
        # Events and results cascade from the foreign key.
        self.db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        with self._seq_lock:
            self._seq.pop(scan_id, None)
        return True

    # ── shaping ───────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row) -> dict[str, Any]:
        def load(value, fallback):
            try:
                return json.loads(value) if value else fallback
            except ValueError:
                return fallback

        started, finished = row["started_at"], row["finished_at"]
        duration = None
        if started:
            duration = round((finished or time.time()) - started, 1)

        return {
            "id": row["id"],
            "target": row["target"],
            "status": row["status"],
            "username": row["username"] if "username" in row.keys() else None,
            "created_at": row["created_at"],
            "started_at": started,
            "finished_at": finished,
            "duration": duration,
            "risk_score": row["risk_score"],
            "risk_label": row["risk_label"],
            "counts": load(row["counts_json"], {}),
            "config": load(row["config_json"], {}),
            "error": row["error"],
            "last_seq": row["last_seq"],
        }
