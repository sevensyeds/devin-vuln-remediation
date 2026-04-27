"""Status mapping tests — especially transitional pauses that must NOT be terminal."""

from app.status_model import CanonicalStatus, is_terminal, map_devin_to_canonical


def test_running_waiting_for_user_stays_running_not_terminal():
    # Devin is paused awaiting user input — it can resume. Poller must keep watching.
    status = map_devin_to_canonical("running", "waiting_for_user", [], None)
    assert status == CanonicalStatus.RUNNING
    assert not is_terminal(status)


def test_running_waiting_for_approval_stays_running_not_terminal():
    status = map_devin_to_canonical("running", "waiting_for_approval", [], None)
    assert status == CanonicalStatus.RUNNING
    assert not is_terminal(status)


def test_running_with_pr_maps_to_pr_opened():
    status = map_devin_to_canonical(
        "running",
        "working",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        None,
    )
    assert status == CanonicalStatus.PR_OPENED


def test_exit_with_pr_and_good_structured_output_succeeds():
    structured = {
        "vulnerability_fixed": True,
        "needs_human_review": False,
        "backward_compatibility_risk": "none",
    }
    status = map_devin_to_canonical(
        "exit",
        "finished",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        structured,
    )
    assert status == CanonicalStatus.SUCCEEDED
    assert is_terminal(status)


def test_exit_with_pr_but_needs_human_review_flagged_is_terminal_review():
    structured = {
        "vulnerability_fixed": True,
        "needs_human_review": True,
        "backward_compatibility_risk": "medium",
    }
    status = map_devin_to_canonical(
        "exit",
        "finished",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        structured,
    )
    assert status == CanonicalStatus.NEEDS_HUMAN_REVIEW
    assert is_terminal(status)


def test_exit_with_pr_but_high_backcompat_risk_is_terminal_review():
    structured = {
        "vulnerability_fixed": True,
        "needs_human_review": False,
        "backward_compatibility_risk": "high",
    }
    status = map_devin_to_canonical(
        "exit",
        "finished",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        structured,
    )
    assert status == CanonicalStatus.NEEDS_HUMAN_REVIEW


def test_exit_without_pr_is_failed():
    status = map_devin_to_canonical("exit", "finished", [], None)
    assert status == CanonicalStatus.FAILED


def test_suspended_usage_limit_is_failed():
    status = map_devin_to_canonical("suspended", "usage_limit_exceeded", [], None)
    assert status == CanonicalStatus.FAILED


def test_error_is_failed():
    status = map_devin_to_canonical("error", None, [], None)
    assert status == CanonicalStatus.FAILED


# --- running + finished branch ----------------------------------------------
# `running + status_detail: finished` is a real Devin state (agent's work is done, session
# hasn't flipped to `exit` yet). These tests lock in the terminal evaluation so we don't
# loop forever on a session that Devin considers complete.


def test_running_finished_with_pr_and_clean_output_succeeds():
    structured = {
        "vulnerability_fixed": True,
        "needs_human_review": False,
        "backward_compatibility_risk": "low",
    }
    status = map_devin_to_canonical(
        "running",
        "finished",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        structured,
    )
    assert status == CanonicalStatus.SUCCEEDED
    assert is_terminal(status)


def test_running_finished_with_pr_but_no_structured_output_needs_review():
    status = map_devin_to_canonical(
        "running",
        "finished",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        None,
    )
    assert status == CanonicalStatus.NEEDS_HUMAN_REVIEW


def test_running_finished_without_pr_is_failed():
    status = map_devin_to_canonical("running", "finished", [], None)
    assert status == CanonicalStatus.FAILED


# --- suspended branch -------------------------------------------------------
# Devin suspends for a range of reasons. Cost/billing caps and explicit errors must fail.
# User-requested suspend routes to review. Everything else (typically inactivity) is
# post-completion quiescence — evaluate like exit when a PR is present.


def test_suspended_inactivity_with_pr_and_clean_output_succeeds():
    structured = {
        "vulnerability_fixed": True,
        "needs_human_review": False,
        "backward_compatibility_risk": "none",
    }
    status = map_devin_to_canonical(
        "suspended",
        "inactivity",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        structured,
    )
    assert status == CanonicalStatus.SUCCEEDED


def test_suspended_inactivity_with_pr_no_structured_output_needs_review():
    status = map_devin_to_canonical(
        "suspended",
        "inactivity",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        None,
    )
    assert status == CanonicalStatus.NEEDS_HUMAN_REVIEW


def test_suspended_inactivity_without_pr_is_failed():
    status = map_devin_to_canonical("suspended", "inactivity", [], None)
    assert status == CanonicalStatus.FAILED


def test_suspended_out_of_credits_is_failed_even_with_pr():
    structured = {"vulnerability_fixed": True, "needs_human_review": False}
    status = map_devin_to_canonical(
        "suspended",
        "out_of_credits",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        structured,
    )
    assert status == CanonicalStatus.FAILED


def test_suspended_user_request_routes_to_review():
    status = map_devin_to_canonical(
        "suspended",
        "user_request",
        [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
        None,
    )
    assert status == CanonicalStatus.NEEDS_HUMAN_REVIEW
