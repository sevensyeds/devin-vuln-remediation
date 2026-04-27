"""Minimal GitHub REST client for the remediation lifecycle.

We need exactly four operations:
- find an open issue by the hidden canonical marker (idempotency)
- create an issue with that marker embedded in the body
- add a comment to an issue
- close an issue

No PyGithub dependency — httpx keeps the container small and avoids an extra abstraction.
"""

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from app.config import settings

log = logging.getLogger(__name__)


def _canonical_marker(canonical_id: str) -> str:
    return f"<!-- canonical:{canonical_id} -->"


@dataclass
class GitHubIssue:
    number: int
    url: str
    title: str
    state: str


class GitHubClient:
    def __init__(
        self,
        repo: Optional[str] = None,
        token: Optional[str] = None,
        base_url: str = "https://api.github.com",
    ) -> None:
        self.repo = repo or settings.github_repo
        self.token = token or settings.github_token
        self.base_url = base_url
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15.0,
        )

    def close(self) -> None:
        self._client.close()

    def find_issue_by_marker(self, canonical_id: str) -> Optional[GitHubIssue]:
        """Return an OPEN issue carrying `<!-- canonical:<canonical_id> -->` in its body.

        We gate on is:open both in the search query AND in the Python-side check so a
        wiped SQLite state can't resurrect a historically closed issue.
        """
        marker = _canonical_marker(canonical_id)
        q = f'repo:{self.repo} is:issue is:open "{marker}"'
        resp = self._client.get(f"{self.base_url}/search/issues", params={"q": q})
        resp.raise_for_status()
        items = resp.json().get("items", [])
        for item in items:
            body = item.get("body") or ""
            if marker in body and item.get("state") == "open":
                return GitHubIssue(
                    number=item["number"],
                    url=item["html_url"],
                    title=item["title"],
                    state=item["state"],
                )
        return None

    def create_issue(
        self,
        canonical_id: str,
        title: str,
        body: str,
        labels: Optional[list[str]] = None,
    ) -> GitHubIssue:
        marker = _canonical_marker(canonical_id)
        full_body = f"{marker}\n\n{body}"
        payload: dict = {"title": title, "body": full_body}
        if labels:
            payload["labels"] = labels
        resp = self._client.post(f"{self.base_url}/repos/{self.repo}/issues", json=payload)
        resp.raise_for_status()
        data = resp.json()
        log.info("created github issue #%s for %s", data["number"], canonical_id)
        return GitHubIssue(
            number=data["number"],
            url=data["html_url"],
            title=data["title"],
            state=data["state"],
        )

    def add_comment(self, issue_number: int, body: str) -> None:
        resp = self._client.post(
            f"{self.base_url}/repos/{self.repo}/issues/{issue_number}/comments",
            json={"body": body},
        )
        resp.raise_for_status()

    def close_issue(self, issue_number: int, reason: str = "completed") -> None:
        resp = self._client.patch(
            f"{self.base_url}/repos/{self.repo}/issues/{issue_number}",
            json={"state": "closed", "state_reason": reason},
        )
        resp.raise_for_status()


def issue_body_for(ticket) -> str:
    """Render a short issue body for a canonical ticket. ticket is a CanonicalTicket."""
    return (
        f"**Canonical ticket:** `{ticket.canonical_name}`\n"
        f"**CWE:** {ticket.cwe}\n"
        f"**Severity:** {ticket.severity}\n"
        f"**Eligibility:** `{ticket.eligibility}`\n"
        f"**File:** `{ticket.file_path}:{ticket.line_number}`\n\n"
        f"This issue was created automatically by the remediation control plane. "
        f"Lifecycle events will appear as comments below."
    )
