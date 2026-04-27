"""`/status` JSON rollup. Secondary observability surface for the Loom dashboard slide."""

import json
from datetime import datetime, timezone
from typing import Optional

from app.database import db
from app.status_model import CanonicalStatus


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(s) if s else None


def status_rollup() -> dict:
    with db() as conn:
        tickets = [dict(r) for r in conn.execute("SELECT * FROM tickets").fetchall()]
        sessions = [dict(r) for r in conn.execute("SELECT * FROM sessions").fetchall()]
        last_scan_row = conn.execute(
            "SELECT started_at FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()

    # Index sessions by canonical_id (latest wins) for PR + ACU lookup.
    latest_session_by_ticket: dict[str, dict] = {}
    for s in sessions:
        cid = s["canonical_id"]
        incumbent = latest_session_by_ticket.get(cid)
        if incumbent is None or (s.get("started_at") or "") > (incumbent.get("started_at") or ""):
            latest_session_by_ticket[cid] = s

    tickets_out: dict[str, dict] = {}
    counts = {s.value: 0 for s in CanonicalStatus}
    total_acus = 0.0
    time_to_terminal_samples: list[float] = []

    for t in tickets:
        cid = t["canonical_id"]
        sess = latest_session_by_ticket.get(cid)
        pr_url = sess.get("pr_url") if sess else None
        acus = float(sess.get("acus_consumed") or 0.0) if sess else 0.0
        total_acus += acus

        tickets_out[t["canonical_name"]] = {
            "canonical_id": cid,
            "status": t["status"],
            "pr_url": pr_url,
            "acus": round(acus, 2),
            "issue_url": t["issue_url"],
            "cwe": t["cwe"],
            "severity": t["severity"],
        }
        counts[t["status"]] = counts.get(t["status"], 0) + 1

        # Measure session_start → terminal_at, honestly labeled as "time to terminal".
        if sess and sess.get("terminal_at"):
            start = _parse_iso(sess.get("started_at"))
            end = _parse_iso(sess.get("terminal_at"))
            if start and end:
                time_to_terminal_samples.append((end - start).total_seconds())

    rollup = {
        "total_tickets": len(tickets),
        "succeeded": counts.get(CanonicalStatus.SUCCEEDED.value, 0),
        "needs_human_review": counts.get(CanonicalStatus.NEEDS_HUMAN_REVIEW.value, 0),
        "failed": counts.get(CanonicalStatus.FAILED.value, 0),
        "in_flight": sum(
            counts.get(s.value, 0)
            for s in (
                CanonicalStatus.ISSUE_OPENED,
                CanonicalStatus.SESSION_STARTED,
                CanonicalStatus.RUNNING,
                CanonicalStatus.PR_OPENED,
            )
        ),
        "total_acus": round(total_acus, 2),
        "mean_time_to_terminal_seconds": (
            round(sum(time_to_terminal_samples) / len(time_to_terminal_samples), 1)
            if time_to_terminal_samples
            else None
        ),
    }

    return {
        "last_scan_at": last_scan_row["started_at"] if last_scan_row else None,
        "tickets": tickets_out,
        "rollup": rollup,
    }


def sessions_list() -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT s.*, t.canonical_name, t.issue_url
            FROM sessions s
            JOIN tickets t ON s.canonical_id = t.canonical_id
            ORDER BY s.started_at DESC
            """
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        if d.get("structured_output"):
            try:
                d["structured_output"] = json.loads(d["structured_output"])
            except (json.JSONDecodeError, TypeError):
                pass
        out.append(d)
    return out
