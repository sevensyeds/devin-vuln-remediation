"""Poller regression tests — ordering of the wall-clock timeout vs. Devin state fetch.

The wall-clock limit is a safety net for runaway sessions, NOT a signal about completed
work. Devin sessions can sit idle in post-completion states (e.g. `suspended + inactivity`)
for hours. If the timeout check runs BEFORE the mapper, a session that already landed
a clean PR in the cloud will be force-failed just because the poller was slow to observe
it. These tests lock in the correct ordering: fetch + map first, timeout only fires when
the mapper can't pin down a terminal state.
"""

import tempfile
from pathlib import Path

import pytest

import app.config
from app import poller
from app.database import db, init_db
from app.status_model import CanonicalStatus


class FakeGitHub:
    def __init__(self) -> None:
        self.comments: list[tuple[int, str]] = []

    def add_comment(self, issue_number: int, body: str) -> None:
        self.comments.append((issue_number, body))


class FakeDevin:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def get_session(self, session_id: str) -> dict:
        return self._payload


@pytest.fixture
def isolated_db(monkeypatch):
    """Per-test DB isolation — avoids clobbering the shared settings.db_path that
    other test modules also mutate at import time."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    original = app.config.settings.db_path
    original_wall = app.config.settings.session_max_wall_clock_seconds
    app.config.settings.db_path = tmp.name
    app.config.settings.session_max_wall_clock_seconds = 3600
    init_db()
    yield tmp.name
    Path(tmp.name).unlink(missing_ok=True)
    app.config.settings.db_path = original
    app.config.settings.session_max_wall_clock_seconds = original_wall


def _seed_session(
    canonical_id: str = "YAML-001-abc",
    session_id: str = "devin-sess-1",
    started_at: str = "2020-01-01T00:00:00+00:00",  # ancient — well past wall-clock limit
    canonical_status: CanonicalStatus = CanonicalStatus.RUNNING,
) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO tickets (canonical_id, canonical_name, cwe, severity, eligibility,
                file_path, line_number, code_fingerprint, issue_number, issue_url, status,
                first_detected_at, last_updated_at)
            VALUES (?, 'YAML-001', 'CWE-502', 'high', 'auto_remediate_eligible',
                'examples/utils.py', 261, 'abc', 42, 'https://fake/42', ?,
                '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00')
            """,
            (canonical_id, canonical_status.value),
        )
        conn.execute(
            """
            INSERT INTO sessions (session_id, canonical_id, devin_status,
                devin_status_detail, canonical_status, started_at)
            VALUES (?, ?, 'running', 'working', ?, ?)
            """,
            (session_id, canonical_id, canonical_status.value, started_at),
        )


def test_overdue_session_that_completed_in_cloud_lands_succeeded_not_failed(isolated_db):
    """Regression: a session past the wall-clock limit but returning a clean terminal
    state from Devin must be evaluated by the mapper, not force-failed by the timeout."""
    _seed_session()
    devin = FakeDevin({
        "status": "suspended",
        "status_detail": "inactivity",
        "pull_requests": [{"pr_url": "https://fake/pr/1", "pr_state": "open"}],
        "structured_output": {
            "vulnerability_fixed": True,
            "needs_human_review": False,
            "backward_compatibility_risk": "low",
        },
        "acus_consumed": 4.2,
    })

    summary = poller.poll_once(devin=devin, github=FakeGitHub())

    assert summary["polled"] == 1
    with db() as conn:
        row = conn.execute(
            "SELECT canonical_status FROM sessions WHERE session_id = 'devin-sess-1'"
        ).fetchone()
    assert row["canonical_status"] == CanonicalStatus.SUCCEEDED.value


def test_overdue_session_still_running_triggers_wall_clock_timeout(isolated_db):
    """The timeout safety net still fires for sessions the mapper considers non-terminal."""
    _seed_session()
    devin = FakeDevin({
        "status": "running",
        "status_detail": "working",
        "pull_requests": [],
        "structured_output": None,
        "acus_consumed": 1.0,
    })

    summary = poller.poll_once(devin=devin, github=FakeGitHub())

    assert summary["terminated"] == 1
    with db() as conn:
        row = conn.execute(
            "SELECT canonical_status FROM sessions WHERE session_id = 'devin-sess-1'"
        ).fetchone()
    assert row["canonical_status"] == CanonicalStatus.FAILED.value
