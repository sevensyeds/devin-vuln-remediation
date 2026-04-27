import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator

from app.config import settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets (
    canonical_id       TEXT PRIMARY KEY,
    canonical_name     TEXT NOT NULL,
    cwe                TEXT NOT NULL,
    severity           TEXT NOT NULL,
    eligibility        TEXT NOT NULL,
    file_path          TEXT NOT NULL,
    line_number        INTEGER,
    code_fingerprint   TEXT NOT NULL,
    issue_number       INTEGER,
    issue_url          TEXT,
    status             TEXT NOT NULL,
    first_detected_at  TEXT NOT NULL,
    last_updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id         TEXT PRIMARY KEY,
    canonical_id       TEXT NOT NULL,
    devin_session_url  TEXT,
    devin_status       TEXT,
    devin_status_detail TEXT,
    canonical_status   TEXT NOT NULL,
    pr_url             TEXT,
    acus_consumed      REAL DEFAULT 0,
    structured_output  TEXT,
    started_at         TEXT NOT NULL,
    terminal_at        TEXT,
    FOREIGN KEY (canonical_id) REFERENCES tickets(canonical_id)
);

CREATE TABLE IF NOT EXISTS events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_id       TEXT NOT NULL,
    session_id         TEXT,
    event_type         TEXT NOT NULL,
    detail             TEXT,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at         TEXT NOT NULL,
    finished_at        TEXT,
    findings_total     INTEGER,
    tickets_created    INTEGER,
    tickets_deduped    INTEGER
);
"""


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def init_db() -> None:
    _ensure_parent_dir(settings.db_path)
    with sqlite3.connect(settings.db_path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
