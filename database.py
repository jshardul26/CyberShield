"""SQLite layer for CyberShield. Shared by server.py (writes) and app.py (reads/updates)."""
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybershield.db")

SEVERITIES = ("info", "low", "medium", "high")
INCIDENT_STATUSES = ("open", "acknowledged", "contained", "resolved")
ACTIVE_STATUSES = ("open", "acknowledged")  # incident still being handled

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    source     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    dest_port  INTEGER,
    message    TEXT,
    severity   TEXT NOT NULL DEFAULT 'info'
);
CREATE TABLE IF NOT EXISTS incidents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    source     TEXT NOT NULL,
    severity   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL REFERENCES events(id),
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    rule        TEXT NOT NULL,
    description TEXT NOT NULL,
    severity    TEXT NOT NULL,
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source, timestamp);
"""


def get_connection():
    """New short-lived connection (two processes share the file, so no global connection)."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_utc():
    """UTC timestamp as 'YYYY-MM-DD HH:MM:SS' (same format SQLite's datetime() uses)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    with get_connection() as conn:
        conn.executescript(SCHEMA)


def _run_insert(sql, params):
    conn = get_connection()
    try:
        with conn:
            return conn.execute(sql, params).lastrowid
    finally:
        conn.close()


def _fetch(sql, params=()):
    conn = get_connection()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


# ---------- writes ----------

def add_event(source, event_type, dest_port, message, severity="info"):
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity: {severity}")
    return _run_insert(
        "INSERT INTO events (timestamp, source, event_type, dest_port, message, severity) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (now_utc(), source, event_type, dest_port, message, severity),
    )


def add_incident(title, source, severity):
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity: {severity}")
    return _run_insert(
        "INSERT INTO incidents (title, source, severity, created_at, status) "
        "VALUES (?, ?, ?, ?, 'open')",
        (title, source, severity, now_utc()),
    )


def add_alert(event_id, incident_id, rule, description, severity):
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity: {severity}")
    return _run_insert(
        "INSERT INTO alerts (event_id, incident_id, rule, description, severity, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (event_id, incident_id, rule, description, severity, now_utc()),
    )


def update_incident_status(incident_id, status):
    """Returns True if an incident was updated."""
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"invalid status: {status}")
    conn = get_connection()
    try:
        with conn:
            cur = conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
            return cur.rowcount == 1
    finally:
        conn.close()


# ---------- reads used by the detector / server ----------

def get_recent_events(source, seconds):
    """Events from one source in the last `seconds` seconds (oldest first)."""
    return _fetch(
        "SELECT * FROM events WHERE source = ? AND timestamp >= datetime('now', ?) ORDER BY id",
        (source, f"-{int(seconds)} seconds"),
    )


def has_recent_alert(incident_id, rule, seconds):
    """True if this incident already got an alert for this rule in the last `seconds` seconds."""
    rows = _fetch(
        "SELECT 1 FROM alerts WHERE incident_id = ? AND rule = ? "
        "AND timestamp >= datetime('now', ?) LIMIT 1",
        (incident_id, rule, f"-{int(seconds)} seconds"),
    )
    return len(rows) > 0


def find_active_incident(source, title):
    """Open/acknowledged incident for this source + title (decision D6), or None."""
    rows = _fetch(
        "SELECT * FROM incidents WHERE source = ? AND title = ? "
        "AND status IN ('open', 'acknowledged') ORDER BY id DESC LIMIT 1",
        (source, title),
    )
    return rows[0] if rows else None


# ---------- reads used by the web pages ----------

def get_events(limit=100, event_type=None, severity=None):
    sql, params = "SELECT * FROM events WHERE 1=1", []
    if event_type:
        sql += " AND event_type = ?"
        params.append(event_type)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return _fetch(sql, params)


def get_alerts(limit=100):
    """Alerts joined with their event and incident (alert status = its incident's status)."""
    return _fetch(
        "SELECT a.id, a.rule, a.description, a.severity, a.timestamp, "
        "       a.event_id, a.incident_id, e.source, e.event_type, i.status "
        "FROM alerts a "
        "JOIN events e ON e.id = a.event_id "
        "JOIN incidents i ON i.id = a.incident_id "
        "ORDER BY a.id DESC LIMIT ?",
        (limit,),
    )


def get_incidents():
    return _fetch(
        "SELECT i.*, (SELECT COUNT(*) FROM alerts a WHERE a.incident_id = i.id) AS alert_count "
        "FROM incidents i ORDER BY i.id DESC"
    )


def get_nodes(active_seconds=60):
    """One row per source seen so far: last_seen, event_count, 'Active'/'Idle' (decision D2)."""
    return _fetch(
        "SELECT source, MAX(timestamp) AS last_seen, COUNT(*) AS event_count, "
        "  CASE WHEN MAX(timestamp) >= datetime('now', ?) THEN 'Active' ELSE 'Idle' END AS status "
        "FROM events GROUP BY source ORDER BY source",
        (f"-{int(active_seconds)} seconds",),
    )


def get_counts():
    """Numbers for the dashboard cards."""
    one = lambda sql: _fetch(sql)[0][0]
    return {
        "events": one("SELECT COUNT(*) FROM events"),
        "alerts": one("SELECT COUNT(*) FROM alerts"),
        "open_incidents": one("SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'acknowledged')"),
        "nodes": one("SELECT COUNT(DISTINCT source) FROM events"),
    }


if __name__ == "__main__":
    init_db()
    print(f"Database ready: {DB_PATH}")