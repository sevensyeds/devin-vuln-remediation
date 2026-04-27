"""Devin API v3 client.

Endpoints used:
- POST /v3/organizations/{org_id}/sessions
- GET  /v3/organizations/{org_id}/sessions/{session_id}
- POST /v3/organizations/{org_id}/sessions/{session_id}/messages (stub)

When MOCK_DEVIN=true, create_session returns a fake session id and get_session advances
through canned responses from tests/mocks/ so we can rehearse the full pipeline offline.
"""

import json
import logging
from pathlib import Path
from typing import Optional

import httpx

from app.config import settings
from app.structured_output import remediation_schema

log = logging.getLogger(__name__)


MOCKS_DIR = Path(__file__).resolve().parent.parent / "tests" / "mocks"


class DevinClient:
    # Class-level so orchestrator and poller share mock state across instances.
    _mock_state: dict[str, dict] = {}
    _mock_session_to_ticket: dict[str, str] = {}

    def __init__(
        self,
        api_key: Optional[str] = None,
        org_id: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self.api_key = api_key or settings.devin_api_key
        self.org_id = org_id or settings.devin_org_id
        self.base_url = (base_url or settings.devin_base_url).rstrip("/")
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    def close(self) -> None:
        self._client.close()

    def create_session(
        self,
        prompt: str,
        canonical_id: str,
        canonical_name: str,
        cwe: str,
        severity: str,
        title: str,
    ) -> dict:
        """Create a Devin session. Returns the session payload (at minimum: session_id, url)."""
        if settings.mock_devin:
            return self._mock_create(canonical_id, title)

        body = {
            "prompt": prompt,
            "repos": [settings.github_repo],
            "tags": [canonical_name, cwe, severity],
            "advanced_mode": "improve",
            "structured_output_schema": remediation_schema(),
            "max_acu_limit": settings.max_acu_per_session,
            "title": title,
        }
        url = f"{self.base_url}/organizations/{self.org_id}/sessions"
        resp = self._client.post(url, json=body)
        resp.raise_for_status()
        data = resp.json()
        log.info("devin session created: %s for %s", data.get("session_id"), canonical_id)
        return data

    def get_session(self, session_id: str) -> dict:
        if settings.mock_devin:
            return self._mock_get(session_id)

        url = f"{self.base_url}/organizations/{self.org_id}/sessions/{session_id}"
        resp = self._client.get(url)
        resp.raise_for_status()
        return resp.json()

    def send_message(self, session_id: str, message: str) -> dict:
        """Stretch: nudge a session that is waiting_for_user. Not wired to the poller in v1."""
        if settings.mock_devin:
            return {"ok": True, "mocked": True}
        url = f"{self.base_url}/organizations/{self.org_id}/sessions/{session_id}/messages"
        resp = self._client.post(url, json={"message": message})
        resp.raise_for_status()
        return resp.json()

    # --- mock mode ---------------------------------------------------------

    def _load_mock(self, name: str) -> dict:
        return json.loads((MOCKS_DIR / name).read_text())

    def _progression_for(self, canonical_name: str) -> list[dict]:
        """Pick a canned progression based on the ticket family."""
        running = self._load_mock("session_running.json")
        if canonical_name == "PICKLE-001":
            terminal = self._load_mock("session_needs_review.json")
        else:
            terminal = self._load_mock("session_finished.json")
        # Two running ticks, then terminal forever.
        return [running, running, terminal]

    # Mock state is stored as { session_id: {"queue": [...], "terminal": {...}} }.
    def _mock_create(self, canonical_id: str, title: str) -> dict:
        # canonical_id prefix is canonical_name, which is what we need for progression selection.
        canonical_name = canonical_id.rsplit("-", 1)[0]
        progression = self._progression_for(canonical_name)
        session_id = f"mock-{canonical_id.lower()}"
        # Stamp each response with a deterministic session id.
        for p in progression:
            p["session_id"] = session_id
            p["url"] = f"https://app.devin.ai/sessions/{session_id}"
        self._mock_state[session_id] = {
            "queue": progression[:-1],   # running ticks, consumed in order
            "terminal": progression[-1], # replayed forever once queue is empty
        }
        self._mock_session_to_ticket[session_id] = canonical_id
        return {
            "session_id": session_id,
            "url": f"https://app.devin.ai/sessions/{session_id}",
            "status": "new",
            "title": title,
        }

    def _mock_get(self, session_id: str) -> dict:
        state = self._mock_state.get(session_id)
        if state is None:
            raise KeyError(f"unknown mock session {session_id}")
        if state["queue"]:
            return state["queue"].pop(0)
        return state["terminal"]
