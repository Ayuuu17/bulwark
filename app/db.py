"""SQLite store for users, sessions, scans and verified domains."""

import json
import sqlite3
import threading
import time
import uuid

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    grade TEXT,
    score INTEGER,
    summary TEXT,
    result TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS scans_by_user ON scans (user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS verified_domains (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    verified_at REAL NOT NULL,
    PRIMARY KEY (user_id, host)
);
CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
"""

# Columns added after the first release; created on startup if an older database lacks them.
MIGRATIONS = {
    "users": {"terms_version": "TEXT", "terms_accepted_at": "REAL"},
    "scans": {"attested": "INTEGER NOT NULL DEFAULT 0"},
}

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def init() -> None:
    global _conn
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    with _lock:
        _conn.execute("PRAGMA foreign_keys = ON")
        _conn.execute("PRAGMA journal_mode = WAL")  # lets several server workers share the file
        _conn.execute("PRAGMA busy_timeout = 5000")
        _conn.executescript(SCHEMA)
        for table, columns in MIGRATIONS.items():
            existing = {row["name"] for row in _conn.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in existing:
                    _conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        # Scans that were running when the server stopped will never finish.
        _conn.execute("UPDATE scans SET status='failed', error='Server restarted' WHERE status IN ('queued','running')")
        _conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        _conn.commit()


def _execute(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    with _lock:
        cur = _conn.execute(sql, params)
        _conn.commit()
        return cur


def _one(sql: str, params: tuple = ()) -> dict | None:
    with _lock:
        row = _conn.execute(sql, params).fetchone()
    return dict(row) if row else None


def _all(sql: str, params: tuple = ()) -> list[dict]:
    with _lock:
        return [dict(row) for row in _conn.execute(sql, params).fetchall()]


# --- users & sessions ---

def create_user(email: str, password_hash: str, terms_version: str) -> int | None:
    """Returns the new user's id, or None if the email is taken. Records which Terms they accepted, and when."""
    now = time.time()
    try:
        cur = _execute("INSERT INTO users (email, password_hash, created_at, terms_version, terms_accepted_at) "
                       "VALUES (?, ?, ?, ?, ?)", (email, password_hash, now, terms_version, now))
    except sqlite3.IntegrityError:
        return None
    return cur.lastrowid


def get_user(user_id: int) -> dict | None:
    return _one("SELECT * FROM users WHERE id=?", (user_id,))


def get_user_by_email(email: str) -> dict | None:
    return _one("SELECT * FROM users WHERE email=?", (email,))


def set_password(user_id: int, password_hash: str) -> None:
    _execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))


def delete_user(user_id: int) -> None:
    _execute("DELETE FROM users WHERE id=?", (user_id,))  # cascades to sessions, scans, domains


def create_session(token_hash: str, user_id: int, expires_at: float) -> None:
    _execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
             (token_hash, user_id, expires_at))


def session_user(token_hash: str) -> dict | None:
    return _one(
        "SELECT users.id, users.email, users.created_at FROM sessions JOIN users ON users.id = sessions.user_id "
        "WHERE sessions.token_hash=? AND sessions.expires_at > ?",
        (token_hash, time.time()),
    )


def delete_session(token_hash: str) -> None:
    _execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))


def delete_user_sessions(user_id: int) -> None:
    _execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


# --- scans ---

def create_scan(user_id: int, kind: str, target: str, attested: bool = False) -> str:
    """`attested` records that the user confirmed they own (or may scan) an uploaded codebase or app."""
    scan_id = uuid.uuid4().hex
    _execute("INSERT INTO scans (id, user_id, kind, target, status, created_at, attested) "
             "VALUES (?, ?, ?, ?, 'queued', ?, ?)", (scan_id, user_id, kind, target, time.time(), int(attested)))
    return scan_id


def update_scan(scan_id: str, status: str, result: dict | None = None, error: str | None = None) -> None:
    result = result or {}
    _execute(
        "UPDATE scans SET status=?, grade=?, score=?, summary=?, result=?, error=? WHERE id=?",
        (status, result.get("grade"), result.get("score"),
         json.dumps(result["summary"]) if "summary" in result else None,
         json.dumps(result) if result else None, error, scan_id),
    )


def get_scan(scan_id: str, user_id: int) -> dict | None:
    scan = _one("SELECT * FROM scans WHERE id=? AND user_id=?", (scan_id, user_id))
    if scan:
        scan["result"] = json.loads(scan["result"]) if scan["result"] else None
        scan["summary"] = json.loads(scan["summary"]) if scan["summary"] else None
    return scan


def list_scans(user_id: int, limit: int = 200) -> list[dict]:
    scans = _all(
        "SELECT id, kind, target, status, created_at, grade, score, summary, error FROM scans "
        "WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
        (user_id, limit),
    )
    for scan in scans:
        scan["summary"] = json.loads(scan["summary"]) if scan["summary"] else None
    return scans


def delete_scan(scan_id: str, user_id: int) -> bool:
    return _execute("DELETE FROM scans WHERE id=? AND user_id=?", (scan_id, user_id)).rowcount > 0


def count_recent_scans(user_id: int, seconds: int) -> int:
    row = _one("SELECT COUNT(*) AS n FROM scans WHERE user_id=? AND created_at > ?", (user_id, time.time() - seconds))
    return row["n"]


# --- verified domains ---

def _ttl() -> float:
    return config.VERIFICATION_TTL_DAYS * 86400


def mark_verified(user_id: int, host: str, method: str) -> None:
    _execute("INSERT OR REPLACE INTO verified_domains (user_id, host, method, verified_at) VALUES (?, ?, ?, ?)",
             (user_id, host, method, time.time()))


def is_verified(user_id: int, host: str) -> bool:
    row = _one("SELECT verified_at FROM verified_domains WHERE user_id=? AND host=?", (user_id, host))
    return bool(row) and time.time() - row["verified_at"] < _ttl()


def list_domains(user_id: int) -> list[dict]:
    domains = _all("SELECT host, method, verified_at FROM verified_domains WHERE user_id=? ORDER BY host", (user_id,))
    for domain in domains:
        domain["expires_at"] = domain["verified_at"] + _ttl()
        domain["expired"] = domain["expires_at"] < time.time()
    return domains


def delete_domain(user_id: int, host: str) -> bool:
    return _execute("DELETE FROM verified_domains WHERE user_id=? AND host=?", (user_id, host)).rowcount > 0


# --- password resets ---

def create_reset(token_hash: str, user_id: int, expires_at: float) -> None:
    _execute("DELETE FROM password_resets WHERE user_id=?", (user_id,))  # only the newest link works
    _execute("INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
             (token_hash, user_id, expires_at))


def consume_reset(token_hash: str) -> int | None:
    """Marks a valid, unused, unexpired token as used and returns its user id."""
    with _lock:
        row = _conn.execute("SELECT user_id FROM password_resets WHERE token_hash=? AND used=0 AND expires_at > ?",
                            (token_hash, time.time())).fetchone()
        if row is None:
            return None
        _conn.execute("UPDATE password_resets SET used=1 WHERE token_hash=?", (token_hash,))
        _conn.commit()
        return row["user_id"]


# --- privacy: retention and export ---

def purge_expired(retention_days: int) -> int:
    """Deletes expired sessions/reset links and reports older than the retention period. Returns reports deleted."""
    now = time.time()
    _execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    _execute("DELETE FROM password_resets WHERE expires_at < ? OR used=1", (now,))
    if retention_days <= 0:
        return 0
    return _execute("DELETE FROM scans WHERE created_at < ? AND status NOT IN ('queued', 'running')",
                    (now - retention_days * 86400,)).rowcount


def export_user(user_id: int) -> dict:
    user = _one("SELECT email, created_at, terms_version, terms_accepted_at FROM users WHERE id=?", (user_id,))
    domains = _all("SELECT host, method, verified_at FROM verified_domains WHERE user_id=? ORDER BY host", (user_id,))
    scans = _all("SELECT id, kind, target, status, created_at, attested, result, error FROM scans "
                 "WHERE user_id=? ORDER BY created_at DESC", (user_id,))
    for scan in scans:
        scan["result"] = json.loads(scan["result"]) if scan["result"] else None
    return {"account": user, "verified_domains": domains, "scans": scans}
