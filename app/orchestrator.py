"""The pipeline: scan → curate → dedupe → issue → session → persist.

Runs under two entrypoints — the APScheduler cron job and `POST /scan` — which go through
the exact same function so there is no drift between scheduled and manual flows.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from app.config import settings
from app.database import db
from app.devin_client import DevinClient
from app.github_client import GitHubClient, issue_body_for
from app.policy import CanonicalTicket, curate
from app.prompts import prompt_for
from app.scanner import run_bandit
from app.status_model import CanonicalStatus, is_terminal

log = logging.getLogger(__name__)

# Serialize run_scan so the scheduler job and POST /scan can't interleave and
# race on the tickets-table read → GitHub+Devin create path. Both callers go
# through run_in_threadpool, so a plain threading.Lock is the right primitive.
_SCAN_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_scan(
    github: Optional[GitHubClient] = None,
    devin: Optional[DevinClient] = None,
) -> dict:
    """Execute one full scan → remediate cycle. Idempotent. Serialized by _SCAN_LOCK."""
    if not _SCAN_LOCK.acquire(blocking=False):
        log.info("run_scan skipped: another scan is already in progress")
        return {"skipped": True, "reason": "scan_in_progress", "started_at": _now()}
    try:
        return _run_scan_locked(github, devin)
    finally:
        _SCAN_LOCK.release()


def _run_scan_locked(
    github: Optional[GitHubClient],
    devin: Optional[DevinClient],
) -> dict:
    gh = github or GitHubClient()
    dv = devin or DevinClient()
    summary = {
        "started_at": _now(),
        "tickets_created": 0,
        "tickets_deduped": 0,
        "sessions_started": 0,
        "sessions_skipped_over_cap": 0,
    }

    # 1. Scan
    findings = run_bandit(tests=["B506", "B324", "B303", "B301", "B403"])
    log.info("bandit returned %d findings after test-filter", len(findings))

    # 2. Curate
    tickets = curate(findings)
    log.info("curated %d canonical tickets", len(tickets))

    scan_id = _record_scan_start(len(findings))

    # 3. Iterate tickets
    for ticket in tickets:
        state = _process_ticket(ticket, gh, dv, summary)
        log.info("ticket %s → %s", ticket.canonical_id, state)

    _record_scan_end(scan_id, summary)
    summary["finished_at"] = _now()
    return summary


def _process_ticket(
    ticket: CanonicalTicket,
    gh: GitHubClient,
    dv: DevinClient,
    summary: dict,
) -> str:
    """Idempotently walk a ticket through issue → session creation."""
    existing = _get_ticket_row(ticket.canonical_id)

    if existing is None:
        issue = gh.find_issue_by_marker(ticket.canonical_id)
        if issue is None:
            issue = gh.create_issue(
                canonical_id=ticket.canonical_id,
                title=f"{ticket.canonical_name}: {ticket.cwe} in {ticket.file_path}",
                body=issue_body_for(ticket),
                labels=["security", "devin-remediation"],
            )
            gh.add_comment(
                issue.number,
                f"Finding detected by scheduled scan — `{ticket.canonical_name}` "
                f"({ticket.cwe}, severity: {ticket.severity}).",
            )
        _insert_ticket(ticket, issue.number, issue.url, CanonicalStatus.ISSUE_OPENED)
        summary["tickets_created"] += 1
    else:
        # Same canonical id already tracked — dedupe.
        summary["tickets_deduped"] += 1
        if existing["status"] in (
            CanonicalStatus.SUCCEEDED.value,
            CanonicalStatus.FAILED.value,
            CanonicalStatus.NEEDS_HUMAN_REVIEW.value,
        ):
            return f"deduped:terminal:{existing['status']}"
        if _has_active_session(ticket.canonical_id):
            return "deduped:session_active"
        # Issue exists but no active session — fall through to launch one.

    # Resolve issue number now so we can thread it into the Devin prompt.
    ticket_row = existing or _get_ticket_row(ticket.canonical_id)
    issue_number = ticket_row["issue_number"] if ticket_row else None
    if issue_number is None:
        log.error("no issue_number recorded for %s; aborting session launch", ticket.canonical_id)
        return "failed:missing_issue_number"

    # Check concurrency cap before launching.
    if _active_session_count() >= settings.max_concurrent_sessions:
        summary["sessions_skipped_over_cap"] += 1
        _log_event(ticket.canonical_id, None, "session_deferred", "concurrency_cap_hit")
        return "deferred:over_concurrency_cap"

    # 4. Launch Devin session
    prompt = prompt_for(ticket.canonical_name, issue_number=issue_number)
    title = f"{ticket.canonical_name}: {ticket.cwe} remediation"
    try:
        session = dv.create_session(
            prompt=prompt,
            canonical_id=ticket.canonical_id,
            canonical_name=ticket.canonical_name,
            cwe=ticket.cwe,
            severity=ticket.severity,
            title=title,
        )
    except Exception as e:  # noqa: BLE001 — surface the error, keep other tickets flowing
        log.exception("failed to create devin session for %s", ticket.canonical_id)
        _log_event(ticket.canonical_id, None, "session_create_failed", str(e)[:500])
        _update_ticket_status(ticket.canonical_id, CanonicalStatus.FAILED)
        return "failed:session_create"

    session_id = session["session_id"]
    session_url = session.get("url", "")
    _insert_session(ticket.canonical_id, session_id, session_url)
    _update_ticket_status(ticket.canonical_id, CanonicalStatus.SESSION_STARTED)
    summary["sessions_started"] += 1

    gh.add_comment(
        issue_number,
        f"Devin session started — [{session_id}]({session_url}). "
        f"max_acu_limit={settings.max_acu_per_session}, advanced_mode=improve.",
    )
    return "session_started"


# --- DB helpers --------------------------------------------------------------


def _get_ticket_row(canonical_id: str) -> Optional[dict]:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM tickets WHERE canonical_id = ?", (canonical_id,)
        ).fetchone()
        return dict(row) if row else None


def _insert_ticket(
    ticket: CanonicalTicket,
    issue_number: int,
    issue_url: str,
    status: CanonicalStatus,
) -> None:
    now = _now()
    with db() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO tickets
            (canonical_id, canonical_name, cwe, severity, eligibility,
             file_path, line_number, code_fingerprint, issue_number, issue_url,
             status, first_detected_at, last_updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ticket.canonical_id,
                ticket.canonical_name,
                ticket.cwe,
                ticket.severity,
                ticket.eligibility,
                ticket.file_path,
                ticket.line_number,
                ticket.code_fingerprint,
                issue_number,
                issue_url,
                status.value,
                now,
                now,
            ),
        )
    _log_event(ticket.canonical_id, None, "issue_opened", f"#{issue_number}")


def _insert_session(canonical_id: str, session_id: str, session_url: str) -> None:
    now = _now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO sessions
            (session_id, canonical_id, devin_session_url, canonical_status, started_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, canonical_id, session_url, CanonicalStatus.SESSION_STARTED.value, now),
        )
    _log_event(canonical_id, session_id, "session_started", session_url)


def _update_ticket_status(canonical_id: str, status: CanonicalStatus) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE tickets SET status = ?, last_updated_at = ? WHERE canonical_id = ?",
            (status.value, _now(), canonical_id),
        )


def _has_active_session(canonical_id: str) -> bool:
    with db() as conn:
        rows = conn.execute(
            "SELECT canonical_status FROM sessions WHERE canonical_id = ?",
            (canonical_id,),
        ).fetchall()
    for r in rows:
        try:
            if not is_terminal(CanonicalStatus(r["canonical_status"])):
                return True
        except ValueError:
            continue
    return False


def _active_session_count() -> int:
    with db() as conn:
        rows = conn.execute("SELECT canonical_status FROM sessions").fetchall()
    count = 0
    for r in rows:
        try:
            if not is_terminal(CanonicalStatus(r["canonical_status"])):
                count += 1
        except ValueError:
            continue
    return count


def _log_event(canonical_id: str, session_id: Optional[str], event_type: str, detail: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO events (canonical_id, session_id, event_type, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (canonical_id, session_id, event_type, detail, _now()),
        )


def _record_scan_start(findings_total: int) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, findings_total) VALUES (?, ?)",
            (_now(), findings_total),
        )
        return cur.lastrowid


def _record_scan_end(scan_id: int, summary: dict) -> None:
    with db() as conn:
        conn.execute(
            """
            UPDATE scans SET finished_at = ?, tickets_created = ?, tickets_deduped = ?
            WHERE id = ?
            """,
            (_now(), summary["tickets_created"], summary["tickets_deduped"], scan_id),
        )
