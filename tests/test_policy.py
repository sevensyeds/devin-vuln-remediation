import json
from pathlib import Path

from app.policy import curate
from app.scanner import BanditFinding


MOCKS = Path(__file__).parent / "mocks"


def _load_findings(name: str) -> list[BanditFinding]:
    payload = json.loads((MOCKS / name).read_text())
    return [BanditFinding.from_bandit_result(r) for r in payload["results"]]


def test_curate_picks_canonical_three_and_drops_noise():
    findings = _load_findings("bandit_sample.json")
    tickets = curate(findings)

    names = sorted(t.canonical_name for t in tickets)
    assert names == ["MD5-001", "PICKLE-001", "YAML-001"], names
    # The B101 assert_used finding should not produce a ticket.
    assert len(tickets) == 3


def test_curate_is_deterministic_and_deduped():
    findings = _load_findings("bandit_sample.json")
    first = curate(findings)
    second = curate(findings + findings)  # same findings twice
    assert [t.canonical_id for t in first] == [t.canonical_id for t in second]


def test_canonical_ids_are_stable_hashes():
    findings = _load_findings("bandit_sample.json")
    tickets = curate(findings)
    for t in tickets:
        assert t.canonical_id.startswith(t.canonical_name + "-")
        assert len(t.canonical_id.split("-")[-1]) == 10
