"""Background poller: transitions non-terminal Devin sessions and emits lifecycle events.

Runs every POLL_INTERVAL_SECONDS. Only sessions in non-terminal canonical statuses are
polled. On material status transitions, a GitHub comment is posted and an event row is
written. Sessions that exceed SESSION_MAX_WALL_CLOCK_SECONDS are marked failed as a
safety net.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from app.config import settings
from app.database import db
from app.devin_client import DevinClient
from app.github_client import GitHubClient
from app.status_model import CanonicalStatus, is_terminal, map_devin_to_canonical

log = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def poll_once(
    devin: Optional[DevinClient] = None,
    github: Optional[GitHubClient] = None,
) -> dict:
    """Poll all non-terminal sessions once. Returns a compact summary."""
    dv = devin or DevinClient()
    gh = github or GitHubClient()
    summary = {"polled": 0, "transitions": 0, "terminated": 0}

    for session_row in _fetch_non_terminal_sessions():
        summary["polled"] += 1
        try:
            changed, now_terminal = _poll_one(session_row, dv, gh)
        except Exception:
            log.exception("poll failure for session %s", session_row["session_id"])
            continue
        if changed:
            summary["transitions"] += 1
        if now_terminal:
            summary["terminated"] += 1

    return summary


def _poll_one(session_row: dict, dv: DevinClient, gh: GitHubClient) -> tuple[bool, bool]:
    session_id = session_row["session_id"]
    canonical_id = session_row["canonical_id"]
    prev_canonical = CanonicalStatus(session_row["canonical_status"])

    # Fetch current Devin state + run mapper FIRST. The wall-clock timeout is a safety net
    # for runaway sessions, not a signal about completed work — sessions can legitimately
    # sit in post-completion idle (e.g. `suspended + inactivity`) for hours. Checking the
    # timeout before the fetch would force-fail sessions that already reached a terminal
    # state in the cloud; only fire the timeout when the mapper can't pin down one.
    data = dv.get_session(session_id)
    raw_status = data.get("status", "")
    raw_detail = data.get("status_detail")
    prs = data.get("pull_requests") or []
    structured = data.get("structured_output")
    acus = float(data.get("acus_consumed") or 0.0)

    new_canonical = map_devin_to_canonical(raw_status, raw_detail, prs, structured)

    if not is_terminal(new_canonical):
        started = _parse_iso(session_row["started_at"])
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        if elapsed > settings.session_max_wall_clock_seconds:
            _finalize_timeout(session_row, gh)
            return True, True

    prev_detail = session_row.get("devin_status_detail") or ""
    changed = (
        new_canonical != prev_canonical
        or raw_status != (session_row.get("devin_status") or "")
        or (raw_detail or "") != prev_detail
    )

    # Persist latest session state regardless
    _update_session_state(
        session_id=session_id,
        raw_status=raw_status,
        raw_detail=raw_detail,
        canonical=new_canonical,
        pr_url=prs[0]["pr_url"] if prs else None,
        acus=acus,
        structured=structured,
        terminal=is_terminal(new_canonical),
    )

    if not changed:
        return False, False

    _update_ticket_from_session(canonical_id, new_canonical)
    _emit_comment_on_transition(
        gh=gh,
        canonical_id=canonical_id,
        session_id=session_id,
        prev=prev_canonical,
        now=new_canonical,
        prs=prs,
        structured=structured,
        acus=acus,
        raw_status=raw_status,
        raw_detail=raw_detail,
    )
    _log_event(
        canonical_id,
        session_id,
        f"transition:{prev_canonical.value}->{new_canonical.value}",
        f"devin={raw_status}/{raw_detail}",
    )

    return True, is_terminal(new_canonical)


def _emit_comment_on_transition(
    gh: GitHubClient,
    canonical_id: str,
    session_id: str,
    prev: CanonicalStatus,
    now: CanonicalStatus,
    prs: list,
    structured: Optional[dict],
    acus: float,
    raw_status: str,
    raw_detail: Optional[str],
) -> None:
    issue_number = _issue_number_for(canonical_id)
    if issue_number is None:
        return

    pr_url = prs[0]["pr_url"] if prs else None

    if now == CanonicalStatus.PR_OPENED and prev != CanonicalStatus.PR_OPENED:
        gh.add_comment(issue_number, f"Devin opened PR: {pr_url} (ACUs so far: {acus:.1f}).")
        return

    if now == CanonicalStatus.SUCCEEDED:
        confidence = (structured or {}).get("confidence")
        tag = f" ⚠️ low confidence ({confidence:.2f})" if confidence is not None and confidence < 0.6 else ""
        gh.add_comment(
            issue_number,
            f"✅ Completed — PR: {pr_url} | ACUs: {acus:.1f} | needs_human_review: false{tag}",
        )
        follow_up = (structured or {}).get("recommended_follow_up", "")
        if follow_up:
            gh.add_comment(issue_number, f"Follow-up noted by Devin: {follow_up}")
        return

    if now == CanonicalStatus.NEEDS_HUMAN_REVIEW:
        reason_bits = []
        so = structured or {}
        if so.get("needs_human_review"):
            reason_bits.append("`needs_human_review=true`")
        if so.get("backward_compatibility_risk") == "high":
            reason_bits.append("`backward_compatibility_risk=high`")
        if raw_detail in ("waiting_for_user", "waiting_for_approval"):
            reason_bits.append(f"Devin detail `{raw_detail}`")
        reason = ", ".join(reason_bits) or "structured output flagged uncertainty"
        pr_fragment = f"PR: {pr_url}" if pr_url else "no PR"
        gh.add_comment(
            issue_number,
            f"🔍 Needs human review — {reason}. {pr_fragment} | ACUs: {acus:.1f}",
        )
        return

    if now == CanonicalStatus.FAILED:
        reason = raw_detail or raw_status or "unknown"
        gh.add_comment(
            issue_number,
            f"❌ Remediation failed — reason: `{reason}` | ACUs: {acus:.1f}",
        )
        return

    if now == CanonicalStatus.RUNNING:
        if raw_detail in ("waiting_for_user", "waiting_for_approval"):
            gh.add_comment(
                issue_number,
                f"⏸ Devin paused — `{raw_detail}` (ACUs: {acus:.1f}). "
                f"Still polling; will resume when Devin does.",
            )
            return
        if prev in (CanonicalStatus.SESSION_STARTED, CanonicalStatus.ISSUE_OPENED):
            gh.add_comment(issue_number, f"Devin status: running (ACUs: {acus:.1f}).")
        return


def _finalize_timeout(session_row: dict, gh: GitHubClient) -> None:
    session_id = session_row["session_id"]
    canonical_id = session_row["canonical_id"]
    with db() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET canonical_status = ?, terminal_at = ?
            WHERE session_id = ?
            """,
            (CanonicalStatus.FAILED.value, _now(), session_id),
        )
    _update_ticket_from_session(canonical_id, CanonicalStatus.FAILED)
    issue_number = _issue_number_for(canonical_id)
    if issue_number is not None:
        gh.add_comment(
            issue_number,
            f"❌ Remediation aborted — session {session_id} exceeded "
            f"{settings.session_max_wall_clock_seconds}s wall-clock limit.",
        )
    _log_event(canonical_id, session_id, "wall_clock_timeout", "")


# --- DB helpers --------------------------------------------------------------


def _fetch_non_terminal_sessions() -> list[dict]:
    terminal_vals = tuple(s.value for s in (
        CanonicalStatus.SUCCEEDED,
        CanonicalStatus.NEEDS_HUMAN_REVIEW,
        CanonicalStatus.FAILED,
    ))
    placeholders = ",".join("?" for _ in terminal_vals)
    query = f"SELECT * FROM sessions WHERE canonical_status NOT IN ({placeholders})"
    with db() as conn:
        rows = conn.execute(query, terminal_vals).fetchall()
    return [dict(r) for r in rows]


def _update_session_state(
    session_id: str,
    raw_status: str,
    raw_detail: Optional[str],
    canonical: CanonicalStatus,
    pr_url: Optional[str],
    acus: float,
    structured: Optional[dict],
    terminal: bool,
) -> None:
    with db() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET devin_status = ?,
                devin_status_detail = ?,
                canonical_status = ?,
                pr_url = COALESCE(?, pr_url),
                acus_consumed = ?,
                structured_output = ?,
                terminal_at = COALESCE(terminal_at, ?)
            WHERE session_id = ?
            """,
            (
                raw_status,
                raw_detail,
                canonical.value,
                pr_url,
                acus,
                json.dumps(structured) if structured else None,
                _now() if terminal else None,
                session_id,
            ),
        )


def _update_ticket_from_session(canonical_id: str, canonical: CanonicalStatus) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE tickets SET status = ?, last_updated_at = ? WHERE canonical_id = ?",
            (canonical.value, _now(), canonical_id),
        )


def _issue_number_for(canonical_id: str) -> Optional[int]:
    with db() as conn:
        row = conn.execute(
            "SELECT issue_number FROM tickets WHERE canonical_id = ?", (canonical_id,)
        ).fetchone()
    return int(row["issue_number"]) if row and row["issue_number"] is not None else None


def _log_event(canonical_id: str, session_id: Optional[str], event_type: str, detail: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO events (canonical_id, session_id, event_type, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (canonical_id, session_id, event_type, detail, _now()),
        )
