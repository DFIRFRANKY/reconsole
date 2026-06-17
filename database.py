"""
database.py
-----------
SQLite persistence for reconsole.

Model
    scans     one launch ("job") = selected commands + targets
    runs      one external process invocation (a preset, expanded per-host
              where the tool needs it, or a custom command). Holds the final
              command string, status, and the path to its raw output .txt.
    ports     open/closed ports parsed from nmap (keyed to scan + ip + run)
    findings  smbmap shares / gobuster paths (keyed to scan + ip + run + tool)

Short-lived connections + a write lock make this safe to use from both the
Flask request threads and the background scan worker.
"""

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = "reconsole.db"
_write_lock = threading.Lock()


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                targets_raw TEXT    NOT NULL,
                ip_count    INTEGER NOT NULL DEFAULT 0,
                status      TEXT    NOT NULL DEFAULT 'queued',
                created_at  TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                tool        TEXT    NOT NULL,
                command     TEXT    NOT NULL,
                target_ip   TEXT,                 -- single ip, or NULL for multi-target nmap
                status      TEXT    NOT NULL DEFAULT 'queued',
                error       TEXT,
                output_file TEXT,
                started_at  TEXT,
                finished_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS ports (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER NOT NULL,
                run_id    INTEGER,
                ip        TEXT    NOT NULL,
                port      INTEGER NOT NULL,
                protocol  TEXT,
                state     TEXT,
                service   TEXT,
                product   TEXT,
                version   TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                run_id      INTEGER,
                tool        TEXT    NOT NULL,
                ip          TEXT,
                title       TEXT    NOT NULL,
                detail      TEXT,
                created_at  TEXT    NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_runs_scan     ON runs(scan_id);
            CREATE INDEX IF NOT EXISTS idx_ports_scan    ON ports(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            """
        )


# ---- scans ----
def create_scan(targets_raw: str, ip_count: int) -> int:
    with _write_lock, get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (targets_raw, ip_count, status, created_at) "
            "VALUES (?, ?, 'running', ?)",
            (targets_raw, ip_count, utcnow()),
        )
        return cur.lastrowid


def set_scan_status(scan_id: int, status: str) -> None:
    with _write_lock, get_conn() as conn:
        conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))


# ---- runs ----
def create_run(scan_id: int, tool: str, command: str, target_ip: str = None,
               status: str = "queued") -> int:
    with _write_lock, get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO runs (scan_id, tool, command, target_ip, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, tool, command, target_ip, status),
        )
        return cur.lastrowid


def set_run_status(run_id: int, status: str) -> None:
    """Flip a run's status; stamp started_at when it actually begins running."""
    with _write_lock, get_conn() as conn:
        if status == "running":
            conn.execute("UPDATE runs SET status=?, started_at=? WHERE id=?",
                         (status, utcnow(), run_id))
        else:
            conn.execute("UPDATE runs SET status=? WHERE id=?", (status, run_id))


def set_run_output(run_id: int, output_file: str) -> None:
    """Record the output-file path as soon as the run starts, so the GUI can
    link to it (and the user can watch it fill) while the scan is in progress."""
    with _write_lock, get_conn() as conn:
        conn.execute("UPDATE runs SET output_file=? WHERE id=?", (output_file, run_id))


def finish_run(run_id: int, status: str, error: str = None) -> None:
    with _write_lock, get_conn() as conn:
        conn.execute(
            "UPDATE runs SET status=?, error=?, finished_at=? WHERE id=?",
            (status, error, utcnow(), run_id),
        )


def get_run(run_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None


def delete_run(run_id: int):
    """Remove a single run and its parsed results. Returns the output_file path
    (so the caller can delete the file on disk)."""
    with _write_lock, get_conn() as conn:
        row = conn.execute("SELECT output_file FROM runs WHERE id=?", (run_id,)).fetchone()
        outfile = row["output_file"] if row else None
        conn.execute("DELETE FROM ports WHERE run_id=?", (run_id,))
        conn.execute("DELETE FROM findings WHERE run_id=?", (run_id,))
        conn.execute("DELETE FROM runs WHERE id=?", (run_id,))
    return outfile


def reset_all() -> None:
    """Wipe every scan, run, port and finding. (FK cascade would handle most of
    this from scans, but we clear all tables explicitly to be safe.)"""
    with _write_lock, get_conn() as conn:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM ports")
        conn.execute("DELETE FROM runs")
        conn.execute("DELETE FROM scans")


# ---- results ----
def add_port(scan_id, run_id, ip, port, protocol, state, service, product, version) -> None:
    with _write_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO ports (scan_id, run_id, ip, port, protocol, state, service, product, version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, run_id, ip, port, protocol, state, service, product, version),
        )


def add_finding(scan_id, run_id, tool, ip, title, detail=None) -> None:
    with _write_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO findings (scan_id, run_id, tool, ip, title, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, run_id, tool, ip, title, detail, utcnow()),
        )


# ---- queries for the UI ----
def list_scans(limit: int = 50):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def list_runs(scan_id: int = None):
    with get_conn() as conn:
        if scan_id:
            rows = conn.execute("SELECT * FROM runs WHERE scan_id=? ORDER BY id DESC", (scan_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 200").fetchall()
        return [dict(r) for r in rows]


def open_ports_by_ip():
    """All open ports/services grouped (in Python) by IP — powers the nmap widget."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ip, port, protocol, state, service, product, version, run_id "
            "FROM ports WHERE state='open' ORDER BY ip, port"
        ).fetchall()
    grouped = {}
    for r in rows:
        grouped.setdefault(r["ip"], []).append(dict(r))
    return grouped


def findings_by_ip(tool: str):
    """Findings for a given tool grouped by IP — powers smbmap / gobuster widgets."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ip, title, detail, run_id FROM findings WHERE tool=? ORDER BY ip, id",
            (tool,),
        ).fetchall()
    grouped = {}
    for r in rows:
        key = r["ip"] or "(unspecified)"
        grouped.setdefault(key, []).append(dict(r))
    return grouped


if __name__ == "__main__":
    init_db()
    print("Initialised", DB_PATH)
