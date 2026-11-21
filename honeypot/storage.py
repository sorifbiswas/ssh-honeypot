"""SQLite storage layer for honeypot events."""
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.environ.get("HONEYPOT_DB", "data/honeypot.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER,
    client_banner TEXT
);
CREATE TABLE IF NOT EXISTS auth_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT,
    password TEXT,
    success INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT,
    command TEXT
);
CREATE TABLE IF NOT EXISTS ip_info (
    ip TEXT PRIMARY KEY,
    country TEXT,
    city TEXT,
    asn TEXT,
    org TEXT,
    looked_up TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(ip);
CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_attempts(ts);
"""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    def __init__(self, path=DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def _exec(self, sql, params=()):
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def log_connection(self, ip, port, client_banner=None):
        self._exec(
            "INSERT INTO connections (ts, ip, port, client_banner) VALUES (?,?,?,?)",
            (_now(), ip, port, client_banner),
        )

    def log_auth(self, ip, username, password, success=False):
        self._exec(
            "INSERT INTO auth_attempts (ts, ip, username, password, success) VALUES (?,?,?,?,?)",
            (_now(), ip, username, password, int(success)),
        )

    def log_command(self, ip, username, command):
        self._exec(
            "INSERT INTO commands (ts, ip, username, command) VALUES (?,?,?,?)",
            (_now(), ip, username, command),
        )

    def unenriched_ips(self):
        with self._lock:
            rows = self._conn.execute(
                """SELECT DISTINCT ip FROM auth_attempts
                   WHERE ip NOT IN (SELECT ip FROM ip_info)"""
            ).fetchall()
        return [r[0] for r in rows]

    def save_ip_info(self, ip, country, city, asn, org):
        self._exec(
            "INSERT OR REPLACE INTO ip_info VALUES (?,?,?,?,?,?)",
            (ip, country, city, asn, org, _now()),
        )
