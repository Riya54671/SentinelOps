import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path("data/alerts.db")
ALERTS_JSON = Path("data/alerts.json")

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    scenario TEXT,
    timestamp TEXT,
    source TEXT,
    rule TEXT,
    host TEXT,
    user TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    description TEXT,
    raw_severity TEXT
);
CREATE INDEX IF NOT EXISTS idx_host ON alerts(host);
CREATE INDEX IF NOT EXISTS idx_user ON alerts(user);
CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_dest_ip ON alerts(dest_ip);
CREATE INDEX IF NOT EXISTS idx_ts ON alerts(timestamp);
"""

COLUMNS = ["alert_id", "scenario", "timestamp", "source", "rule", "host",
           "user", "src_ip", "dest_ip", "description", "raw_severity"]


def _connect(db_path=DB_PATH):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DB_PATH):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)


def add_alert(alert: dict, db_path=DB_PATH):
    init_db(db_path)
    values = [alert.get(c, "") for c in COLUMNS]
    placeholders = ",".join("?" * len(COLUMNS))
    with _connect(db_path) as conn:
        conn.execute(
            f"INSERT OR REPLACE INTO alerts ({','.join(COLUMNS)}) VALUES ({placeholders})",
            values,
        )


def load_seed_alerts(db_path=DB_PATH, json_path=ALERTS_JSON):
    init_db(db_path)
    with open(json_path, encoding="utf-8") as f:
        for alert in json.load(f):
            add_alert(alert, db_path)


def _rows(cursor):
    return [dict(r) for r in cursor.fetchall()]


def query_by_ip(ip: str, db_path=DB_PATH):
    init_db(db_path)
    with _connect(db_path) as conn:
        return _rows(conn.execute(
            "SELECT * FROM alerts WHERE src_ip=? OR dest_ip=? ORDER BY timestamp",
            (ip, ip)))


def query_by_host(host: str, db_path=DB_PATH):
    init_db(db_path)
    with _connect(db_path) as conn:
        return _rows(conn.execute(
            "SELECT * FROM alerts WHERE host=? ORDER BY timestamp", (host,)))


def query_by_user(user: str, db_path=DB_PATH):
    init_db(db_path)
    with _connect(db_path) as conn:
        return _rows(conn.execute(
            "SELECT * FROM alerts WHERE user=? ORDER BY timestamp", (user,)))


def query_by_time_window(start_iso: str, end_iso: str, db_path=DB_PATH):
    init_db(db_path)
    with _connect(db_path) as conn:
        return _rows(conn.execute(
            "SELECT * FROM alerts WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp",
            (start_iso, end_iso)))


def query_related(alert: dict, window_minutes: int = 120, db_path=DB_PATH):
    """Alerts sharing host, user or IP with `alert` within +/- window_minutes.
    This is what the Correlation Agent will call."""
    init_db(db_path)
    ts = datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
    start = (ts - timedelta(minutes=window_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (ts + timedelta(minutes=window_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    clauses, params = [], []
    for field in ("host", "user"):
        if alert.get(field):
            clauses.append(f"{field}=?")
            params.append(alert[field])
    for field in ("src_ip", "dest_ip"):
        if alert.get(field):
            clauses.append("(src_ip=? OR dest_ip=?)")
            params.extend([alert[field], alert[field]])
    if not clauses:
        return []

    sql = (f"SELECT * FROM alerts WHERE timestamp BETWEEN ? AND ? "
           f"AND alert_id != ? AND ({' OR '.join(clauses)}) ORDER BY timestamp")
    with _connect(db_path) as conn:
        return _rows(conn.execute(
            sql, [start, end, alert.get("alert_id", "")] + params))


if __name__ == "__main__":
    load_seed_alerts()
    print("Loaded alerts. Sample query by host fin-db-01:")
    for a in query_by_host("fin-db-01"):
        print(a["alert_id"], a["rule"])