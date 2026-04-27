"""End-to-end test of the orchestrator + poller under MOCK_DEVIN.

Stubs the scanner (uses the canned bandit JSON) and the GitHub client (captures calls in
memory). Verifies the full pipeline walks from DETECTED → SUCCEEDED or NEEDS_HUMAN_REVIEW
for each canonical ticket.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Mutate the shared settings singleton in place so every module that did
# `from app.config import settings` sees the change. Reloading app.config would
# replace the object and leak stale references into other modules.
import app.config
_TMP_DB = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_TMP_DB.close()
app.config.settings.mock_devin = True
app.config.settings.db_path = _TMP_DB.name

from app import orchestrator, poller
from app.database import init_db
from app.devin_client import DevinClient
from app.scanner import BanditFinding


MOCKS = Path(__file__).parent / "mocks"


class FakeGitHub:
    def __init__(self) -> None:
        self._counter = 100
        self.issues: dict[int, dict] = {}
        self.comments: list[tuple[int, str]] = []

    def find_issue_by_marker(self, canonical_id: str):
        for num, issue in self.issues.items():
            if canonical_id in issue["body"]:
                return type("I", (), issue | {"number": num})
        return None

    def create_issue(self, canonical_id: str, title: str, body: str, labels=None):
        self._counter += 1
        num = self._counter
        self.issues[num] = {
            "number": num,
            "url": f"https://fake/{num}",
            "title": title,
            "body": f"<!-- canonical:{canonical_id} -->\n\n{body}",
            "state": "open",
        }
        return type("I", (), self.issues[num])

    def add_comment(self, issue_number: int, body: str) -> None:
        self.comments.append((issue_number, body))

    def close_issue(self, issue_number: int, reason: str = "completed") -> None:
        self.issues[issue_number]["state"] = "closed"


@pytest.fixture(autouse=True)
def _clean_db():
    # Wipe + reinit the test DB before every test, and clear class-level mock state.
    Path(_TMP_DB.name).unlink(missing_ok=True)
    init_db()
    DevinClient._mock_state.clear()
    DevinClient._mock_session_to_ticket.clear()
    yield


def _load_findings():
    payload = json.loads((MOCKS / "bandit_sample.json").read_text())
    return [BanditFinding.from_bandit_result(r) for r in payload["results"]]


def test_full_pipeline_mock_mode_drives_three_tickets_to_terminal():
    gh = FakeGitHub()
    # Patch the scanner to return canned findings without needing a real Superset tree.
    with patch("app.orchestrator.run_bandit", return_value=_load_findings()):
        summary = orchestrator.run_scan(github=gh)

    assert summary["tickets_created"] == 3, summary
    assert summary["sessions_started"] == 2, (
        "MAX_CONCURRENT_SESSIONS=2 should gate the third launch on the first scan"
    )

    # One more scan tick drives the third session in (first two will have completed after polling).
    for _ in range(5):
        poller.poll_once(github=gh)

    # After polling, the first two should be terminal. The third ticket still has no session.
    with patch("app.orchestrator.run_bandit", return_value=_load_findings()):
        orchestrator.run_scan(github=gh)
    for _ in range(5):
        poller.poll_once(github=gh)

    from app.status_endpoint import status_rollup
    rollup = status_rollup()
    statuses = {name: t["status"] for name, t in rollup["tickets"].items()}

    # YAML + MD5 should land succeeded; PICKLE should land needs_human_review per the
    # mock progression wiring in DevinClient.
    assert statuses.get("YAML-001") == "succeeded", statuses
    assert statuses.get("MD5-001") == "succeeded", statuses
    assert statuses.get("PICKLE-001") == "needs_human_review", statuses

    assert rollup["rollup"]["succeeded"] == 2
    assert rollup["rollup"]["needs_human_review"] == 1
    assert rollup["rollup"]["failed"] == 0

    # GitHub comments should include a ✅ for YAML + MD5 and a 🔍 for PICKLE.
    bodies = [c[1] for c in gh.comments]
    assert any("✅ Completed" in b for b in bodies)
    assert any("🔍 Needs human review" in b for b in bodies)


def test_scan_is_idempotent_no_duplicate_issues():
    gh = FakeGitHub()
    with patch("app.orchestrator.run_bandit", return_value=_load_findings()):
        orchestrator.run_scan(github=gh)
        before = len(gh.issues)
        orchestrator.run_scan(github=gh)
        after = len(gh.issues)
    assert before == after == 3
