from enum import Enum
from typing import Optional


# Devin `suspended` status_detail values that indicate a hard failure regardless of
# whether a PR was opened. Cost caps, billing issues, or explicit errors all land here.
_SUSPENDED_FAILURE_DETAILS = {
    "usage_limit_exceeded",
    "out_of_credits",
    "out_of_quota",
    "no_quota_allocation",
    "payment_declined",
    "org_usage_limit_exceeded",
    "error",
}


def _evaluate_terminal_with_pr(
    pull_requests: list,
    structured_output: Optional[dict],
) -> "CanonicalStatus":
    """Shared terminal evaluation for any branch where Devin has stopped producing work.

    Used by exit, suspended+inactivity, and running+finished when a PR is present.
    """
    if not pull_requests:
        return CanonicalStatus.FAILED
    if structured_output:
        if not structured_output.get("vulnerability_fixed", False):
            return CanonicalStatus.FAILED
        if structured_output.get("needs_human_review", False):
            return CanonicalStatus.NEEDS_HUMAN_REVIEW
        if structured_output.get("backward_compatibility_risk") == "high":
            return CanonicalStatus.NEEDS_HUMAN_REVIEW
        return CanonicalStatus.SUCCEEDED
    # PR exists but we never captured structured output — route to review rather than
    # claiming success on a verdict we never saw.
    return CanonicalStatus.NEEDS_HUMAN_REVIEW


class CanonicalStatus(str, Enum):
    DETECTED = "detected"
    DEDUPED = "deduped"
    ISSUE_OPENED = "issue_opened"
    SESSION_STARTED = "session_started"
    RUNNING = "running"
    PR_OPENED = "pr_opened"
    SUCCEEDED = "succeeded"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    FAILED = "failed"


TERMINAL = {
    CanonicalStatus.SUCCEEDED,
    CanonicalStatus.NEEDS_HUMAN_REVIEW,
    CanonicalStatus.FAILED,
}


def is_terminal(status: CanonicalStatus) -> bool:
    return status in TERMINAL


def map_devin_to_canonical(
    devin_status: str,
    devin_status_detail: Optional[str],
    pull_requests: list,
    structured_output: Optional[dict],
) -> CanonicalStatus:
    """Map Devin's raw status into our canonical vocabulary.

    See devin-api.md for the full table. Terminal states depend on structured_output
    contents so a PR with `needs_human_review: true` doesn't land as succeeded.
    """
    detail = devin_status_detail or ""

    if devin_status in ("new", "creating", "claimed"):
        return CanonicalStatus.SESSION_STARTED

    if devin_status == "running":
        # `running + finished` is a documented Devin state: the agent's work is done but
        # the session hasn't transitioned to `exit` yet. If a PR is present, evaluate it
        # as terminal — otherwise we'd loop forever watching a session that's done.
        if detail == "finished":
            return _evaluate_terminal_with_pr(pull_requests, structured_output)
        # waiting_for_user / waiting_for_approval are PAUSES, not terminal states.
        # Devin can resume; we must keep polling. Surface the nuance in GitHub comments,
        # but stay in RUNNING so the poller doesn't drop the session.
        if pull_requests:
            return CanonicalStatus.PR_OPENED
        return CanonicalStatus.RUNNING

    if devin_status == "exit":
        return _evaluate_terminal_with_pr(pull_requests, structured_output)

    if devin_status == "error":
        return CanonicalStatus.FAILED

    if devin_status == "suspended":
        # Hard failures from cost/billing caps and explicit errors short-circuit regardless
        # of what the session produced.
        if detail in _SUSPENDED_FAILURE_DETAILS:
            return CanonicalStatus.FAILED
        # Explicit user suspend — route to human review, not silent failure.
        if detail == "user_request":
            return CanonicalStatus.NEEDS_HUMAN_REVIEW
        # Otherwise (typically inactivity) Devin has gone idle post-work. If a PR was
        # opened, evaluate like an `exit` branch; if not, treat as failure.
        return _evaluate_terminal_with_pr(pull_requests, structured_output)

    return CanonicalStatus.RUNNING
