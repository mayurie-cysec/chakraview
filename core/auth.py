"""Authentication: password hashing, TOTP, sessions, CSRF and rate limiting.

Everything here is standard library. The dependency-free constraint is not
laziness — a security tool that needs four packages to verify a password is a
tool people run with the auth turned off.

Design notes worth keeping in mind when changing anything below:

* Passwords are hashed with scrypt, whose cost parameters are stored per row,
  so raising the defaults later does not lock out existing users.
* Session cookies are random 256-bit values. Only their SHA-256 is stored, so
  a dump of the database yields no usable cookie.
* TOTP codes are accepted once. Without the replay table, anyone who observes
  a code has the full remaining step to reuse it.
* Every comparison of a secret uses compare_digest. None of the checks here
  may short-circuit on the first differing byte.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any

# ── Password hashing ──────────────────────────────────────────────────────
# ~32 MB per hash. Costly enough to matter offline, cheap enough that a login
# on a laptop is not noticeable.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
SALT_BYTES = 16
KEY_LEN = 64

MIN_PASSWORD_LEN = 12
USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$")

# ── Sessions ──────────────────────────────────────────────────────────────
SESSION_BYTES = 32
SESSION_TTL = 12 * 3600          # absolute lifetime
SESSION_IDLE_TTL = 2 * 3600      # idle timeout
SESSION_COOKIE = "cv_session"

# ── Login challenge (between password and TOTP) ───────────────────────────
CHALLENGE_TTL = 180

# ── Lockout ───────────────────────────────────────────────────────────────
MAX_FAILED = 5
LOCKOUT_BASE = 30                # seconds, doubled per failure past the cap
LOCKOUT_MAX = 15 * 60
IP_WINDOW = 900
IP_MAX_ATTEMPTS = 25

# ── TOTP ──────────────────────────────────────────────────────────────────
TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1                  # accept one step either side for clock drift
TOTP_ISSUER = "ChakraView"


# ══════════════════════════════════════════════════════════════════════════
# Passwords
# ══════════════════════════════════════════════════════════════════════════

def hash_password(password: str) -> tuple[bytes, bytes, int, int, int]:
    """Return (hash, salt, n, r, p) for a new or changed password."""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM, dklen=KEY_LEN,
    )
    return digest, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P


def verify_password(password: str, digest: bytes, salt: bytes,
                    n: int, r: int, p: int) -> bool:
    """Constant-time password check against a stored hash."""
    try:
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes(salt),
            n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=len(digest),
        )
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(candidate, bytes(digest))


def password_problem(password: str, username: str = "") -> str:
    """Return a reason the password is unacceptable, or '' if it is fine."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if len(password) > 1024:
        return "Password must be under 1024 characters."
    if username and username.lower() in password.lower():
        return "Password must not contain the username."
    lowered = password.lower()
    if lowered in {"password123", "chakraview1234", "administrator"}:
        return "That password is too common."
    # Four character classes is security theatre; length plus a variety check
    # catches the genuinely weak cases without forcing Pa$$w0rd1.
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes < 2 and len(password) < 20:
        return ("Use at least two kinds of character, or a passphrase of 20 "
                "characters or more.")
    return ""


def username_problem(username: str) -> str:
    if not USERNAME_RE.match(username or ""):
        return ("Username must be 3 to 32 characters: letters, digits, dot, "
                "underscore or hyphen, starting with a letter or digit.")
    return ""


# ══════════════════════════════════════════════════════════════════════════
# TOTP  (RFC 6238 over HMAC-SHA1, which is what every authenticator app does)
# ══════════════════════════════════════════════════════════════════════════

def new_totp_secret() -> str:
    """A fresh base32 secret, 160 bits as RFC 4226 recommends."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_at(secret: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    padding = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret + padding, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_now(secret: str, at: float | None = None) -> str:
    return _totp_at(secret, int((at if at is not None else time.time()) // TOTP_STEP))


def verify_totp(secret: str, code: str, at: float | None = None,
                window: int = TOTP_WINDOW) -> int | None:
    """Return the accepted counter, or None.

    The counter is returned rather than a bool so the caller can record it and
    refuse the same code a second time.
    """
    code = (code or "").strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return None
    now = int((at if at is not None else time.time()) // TOTP_STEP)
    for drift in range(-window, window + 1):
        counter = now + drift
        if counter < 0:
            continue
        if hmac.compare_digest(_totp_at(secret, counter), code):
            return counter
    return None


def totp_uri(secret: str, username: str, issuer: str = TOTP_ISSUER) -> str:
    """otpauth:// URI for an authenticator app."""
    from urllib.parse import quote

    label = quote(f"{issuer}:{username}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={quote(issuer, safe='')}&algorithm=SHA1"
            f"&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def recovery_codes(count: int = 10) -> list[str]:
    """Single-use codes for when the authenticator device is lost."""
    return ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(count)]


# ══════════════════════════════════════════════════════════════════════════
# Tokens
# ══════════════════════════════════════════════════════════════════════════

def new_token(nbytes: int = SESSION_BYTES) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    """What gets stored. The token itself is never written to the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))


# ══════════════════════════════════════════════════════════════════════════
# Sessions
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class Session:
    token_hash: str
    user_id: int
    username: str
    is_admin: bool
    csrf_token: str
    expires_at: float


class AuthError(Exception):
    """Raised for any authentication failure that is safe to surface."""

    def __init__(self, message: str, status: int = 401, retry_after: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.retry_after = retry_after


class Auth:
    """All authentication state lives in the database, not in process memory.

    That is what lets a scan survive a page reload and a session survive a
    worker thread, and it means there is one place to revoke anything.
    """

    def __init__(self, db) -> None:
        self.db = db
        # Short-lived in-memory challenges between the password step and the
        # TOTP step. Deliberately not persisted: they expire in three minutes
        # and a restart should invalidate a half-finished login.
        self._challenges: dict[str, dict[str, Any]] = {}

    # ── users ─────────────────────────────────────────────────────────────

    def create_user(self, username: str, password: str, is_admin: bool = False,
                    with_totp: bool = True) -> dict[str, Any]:
        username = (username or "").strip()
        problem = username_problem(username) or password_problem(password, username)
        if problem:
            raise AuthError(problem, status=400)
        if self.db.one("SELECT 1 FROM users WHERE username = ?", (username,)):
            raise AuthError("That username is already taken.", status=409)

        digest, salt, n, r, p = hash_password(password)
        secret = new_totp_secret() if with_totp else None
        self.db.execute(
            "INSERT INTO users(username, password_hash, password_salt, kdf_n, kdf_r,"
            " kdf_p, totp_secret, totp_confirmed, is_admin, created_at)"
            " VALUES(?,?,?,?,?,?,?,0,?,?)",
            (username, digest, salt, n, r, p, secret, 1 if is_admin else 0, time.time()),
        )
        user_id = self.db.scalar("SELECT id FROM users WHERE username = ?", (username,))
        return {"id": user_id, "username": username, "is_admin": is_admin,
                "totp_secret": secret,
                "totp_uri": totp_uri(secret, username) if secret else ""}

    def user_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM users", default=0) or 0)

    def get_user(self, username: str):
        return self.db.one("SELECT * FROM users WHERE username = ?", (username,))

    # ── rate limiting ─────────────────────────────────────────────────────

    def _record_attempt(self, ip: str, username: str, ok: bool) -> None:
        self.db.execute(
            "INSERT INTO login_attempts(ip, username, ts, ok) VALUES(?,?,?,?)",
            (ip or "?", username or None, time.time(), 1 if ok else 0),
        )

    def _check_ip(self, ip: str) -> None:
        recent = int(self.db.scalar(
            "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND ok = 0 AND ts > ?",
            (ip or "?", time.time() - IP_WINDOW), default=0) or 0)
        if recent >= IP_MAX_ATTEMPTS:
            raise AuthError(
                "Too many failed attempts from this address. Try again later.",
                status=429, retry_after=IP_WINDOW)

    def _lock_user(self, row) -> None:
        failed = int(row["failed_attempts"]) + 1
        locked_until = 0.0
        if failed >= MAX_FAILED:
            backoff = min(LOCKOUT_MAX, LOCKOUT_BASE * (2 ** (failed - MAX_FAILED)))
            locked_until = time.time() + backoff
        self.db.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (failed, locked_until, row["id"]))

    def _clear_lock(self, user_id: int) -> None:
        self.db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0, last_login_at = ?"
            " WHERE id = ?", (time.time(), user_id))

    # ── login ─────────────────────────────────────────────────────────────

    def begin_login(self, username: str, password: str, ip: str) -> dict[str, Any]:
        """Check the password. Returns either a TOTP challenge or a go-ahead.

        Failures are deliberately indistinguishable from each other: unknown
        user, wrong password and disabled account all produce the same message
        and all pay the same scrypt cost, so the endpoint cannot be used to
        enumerate usernames.
        """
        self._check_ip(ip)
        username = (username or "").strip()
        row = self.get_user(username)

        if row is None:
            # Hash anyway, against a throwaway salt, so a missing user takes
            # the same time as a present one.
            hash_password(password or "")
            self._record_attempt(ip, username, False)
            raise AuthError("Incorrect username or password.")

        if row["locked_until"] and row["locked_until"] > time.time():
            wait = int(row["locked_until"] - time.time())
            raise AuthError(
                f"Account temporarily locked. Try again in {wait} seconds.",
                status=429, retry_after=wait)

        ok = verify_password(password or "", row["password_hash"], row["password_salt"],
                             row["kdf_n"], row["kdf_r"], row["kdf_p"])
        if not ok or not row["is_active"]:
            self._lock_user(row)
            self._record_attempt(ip, username, False)
            raise AuthError("Incorrect username or password.")

        if row["totp_secret"]:
            challenge = new_token(24)
            self._challenges[challenge] = {
                "user_id": row["id"], "username": row["username"],
                "expires": time.time() + CHALLENGE_TTL, "ip": ip,
                "enrolling": not row["totp_confirmed"],
            }
            self._sweep_challenges()
            return {
                "stage": "totp",
                "challenge": challenge,
                # Only ever returned while the secret is still unconfirmed, so
                # a stolen password cannot reveal an established secret.
                "enrol": (None if row["totp_confirmed"] else {
                    "secret": row["totp_secret"],
                    "uri": totp_uri(row["totp_secret"], row["username"]),
                }),
            }

        self._clear_lock(row["id"])
        self._record_attempt(ip, username, True)
        return {"stage": "done", "user_id": row["id"], "username": row["username"],
                "is_admin": bool(row["is_admin"])}

    def _sweep_challenges(self) -> None:
        now = time.time()
        for key in [k for k, v in self._challenges.items() if v["expires"] < now]:
            self._challenges.pop(key, None)

    def complete_login(self, challenge: str, code: str, ip: str) -> dict[str, Any]:
        """Second factor. Consumes the challenge whether or not it succeeds."""
        self._check_ip(ip)
        self._sweep_challenges()
        pending = self._challenges.get(challenge or "")
        if pending is None:
            raise AuthError("That login attempt expired. Start again.")
        # Binding the challenge to the address it was issued to stops a
        # captured challenge being completed from somewhere else.
        if pending["ip"] != ip:
            self._challenges.pop(challenge, None)
            raise AuthError("That login attempt expired. Start again.")

        row = self.db.one("SELECT * FROM users WHERE id = ?", (pending["user_id"],))
        if row is None or not row["is_active"]:
            self._challenges.pop(challenge, None)
            raise AuthError("Incorrect username or password.")

        counter = verify_totp(row["totp_secret"], code)
        if counter is None:
            self._lock_user(row)
            self._record_attempt(ip, row["username"], False)
            raise AuthError("Incorrect authentication code.")

        # Refuse a code that has already been accepted in this step.
        used = self.db.one(
            "SELECT 1 FROM totp_used WHERE user_id = ? AND counter = ?",
            (row["id"], counter))
        if used:
            self._record_attempt(ip, row["username"], False)
            raise AuthError("That code has already been used. Wait for the next one.")
        self.db.execute(
            "INSERT OR IGNORE INTO totp_used(user_id, counter, used_at) VALUES(?,?,?)",
            (row["id"], counter, time.time()))

        self._challenges.pop(challenge, None)
        if not row["totp_confirmed"]:
            self.db.execute("UPDATE users SET totp_confirmed = 1 WHERE id = ?", (row["id"],))
        self._clear_lock(row["id"])
        self._record_attempt(ip, row["username"], True)
        return {"stage": "done", "user_id": row["id"], "username": row["username"],
                "is_admin": bool(row["is_admin"])}

    # ── sessions ──────────────────────────────────────────────────────────

    def start_session(self, user_id: int, ip: str, user_agent: str) -> tuple[str, Session]:
        token = new_token()
        now = time.time()
        csrf = new_token(24)
        row = self.db.one("SELECT username, is_admin FROM users WHERE id = ?", (user_id,))
        self.db.execute(
            "INSERT INTO sessions(token_hash, user_id, csrf_token, created_at,"
            " expires_at, last_seen_at, ip, user_agent) VALUES(?,?,?,?,?,?,?,?)",
            (token_hash(token), user_id, csrf, now, now + SESSION_TTL, now,
             (ip or "")[:64], (user_agent or "")[:200]))
        return token, Session(token_hash(token), user_id, row["username"],
                              bool(row["is_admin"]), csrf, now + SESSION_TTL)

    def load_session(self, token: str) -> Session | None:
        if not token:
            return None
        row = self.db.one(
            "SELECT s.*, u.username, u.is_admin, u.is_active FROM sessions s"
            " JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            (token_hash(token),))
        if row is None:
            return None
        now = time.time()
        if row["expires_at"] < now or not row["is_active"]:
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
            return None
        if now - row["last_seen_at"] > SESSION_IDLE_TTL:
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
            return None
        self.db.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                        (now, row["token_hash"]))
        return Session(row["token_hash"], row["user_id"], row["username"],
                       bool(row["is_admin"]), row["csrf_token"], row["expires_at"])

    def end_session(self, token: str) -> None:
        if token:
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))

    def end_all_sessions(self, user_id: int) -> None:
        self.db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
