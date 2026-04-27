"""Policy / curation layer.

Converts raw Bandit findings into a small number of CURATED remediation tickets. Only
tickets in the canonical portfolio are forwarded to Devin. Everything else is ignored.

This is where the system stops being a Bandit wrapper and becomes a remediation control
plane: scanner output → policy decisions → tickets.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

from app.scanner import BanditFinding


@dataclass
class CanonicalTicket:
    canonical_id: str        # deterministic: YAML-001-<hash>
    canonical_name: str      # YAML-001 | MD5-001 | PICKLE-001
    cwe: str                 # "CWE-502" etc.
    severity: str            # high | medium | low
    eligibility: str         # auto_remediate_eligible | review_required
    file_path: str
    line_number: int
    code_fingerprint: str    # hash of file+line+snippet


@dataclass
class PolicyRule:
    canonical_name: str
    bandit_test_ids: tuple[str, ...]    # e.g. ("B506",)
    path_must_contain: tuple[str, ...]  # e.g. ("examples/utils.py",)
    cwe: str
    severity: str
    eligibility: str


# Rules are intentionally narrow. The goal is to map scanner noise to the exact
# files we've already investigated and written bounded Devin prompts for.
RULES: list[PolicyRule] = [
    PolicyRule(
        canonical_name="YAML-001",
        bandit_test_ids=("B506",),
        path_must_contain=("examples/utils.py",),
        cwe="CWE-502",
        severity="high",
        eligibility="auto_remediate_eligible",
    ),
    PolicyRule(
        canonical_name="MD5-001",
        bandit_test_ids=("B324", "B303"),
        path_must_contain=("utils/hashing.py",),
        cwe="CWE-327",
        severity="medium",
        eligibility="auto_remediate_eligible",
    ),
    PolicyRule(
        canonical_name="PICKLE-001",
        bandit_test_ids=("B301", "B403"),
        # Both the codec registration and its usage are valid entry points; bandit
        # most reliably lands on metastore_cache.py.
        path_must_contain=("extensions/metastore_cache.py", "key_value/types.py"),
        cwe="CWE-502",
        severity="high",
        eligibility="auto_remediate_eligible",
    ),
]


def _fingerprint(finding: BanditFinding) -> str:
    """Deterministic hash used for canonical_id + duplicate detection."""
    normalized = "|".join([finding.filename, str(finding.line_number), finding.code.strip()])
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:10]


def _matches_rule(finding: BanditFinding, rule: PolicyRule) -> bool:
    if finding.test_id not in rule.bandit_test_ids:
        return False
    return any(fragment in finding.filename for fragment in rule.path_must_contain)


def curate(findings: list[BanditFinding]) -> list[CanonicalTicket]:
    """Convert raw Bandit findings into the curated canonical portfolio.

    Duplicates (same rule + same fingerprint) are collapsed to a single ticket. Findings
    that don't match any rule are dropped — we deliberately don't auto-remediate arbitrary
    Bandit hits.
    """
    # Dedupe by canonical_name, not canonical_id: multiple Bandit findings of the same
    # class in the same file (e.g. pickle.loads + pickle.dumps on adjacent lines) map to
    # ONE remediation because the bounded Devin prompt is identical — running two sessions
    # wastes ACUs. Keep the first finding encountered as the representative.
    seen_names: set[str] = set()
    tickets: list[CanonicalTicket] = []

    for finding in findings:
        rule = _first_matching_rule(finding)
        if rule is None:
            continue

        if rule.canonical_name in seen_names:
            continue
        seen_names.add(rule.canonical_name)

        fp = _fingerprint(finding)
        canonical_id = f"{rule.canonical_name}-{fp}"

        tickets.append(
            CanonicalTicket(
                canonical_id=canonical_id,
                canonical_name=rule.canonical_name,
                cwe=rule.cwe,
                severity=rule.severity,
                eligibility=rule.eligibility,
                file_path=finding.filename,
                line_number=finding.line_number,
                code_fingerprint=fp,
            )
        )

    return tickets


def _first_matching_rule(finding: BanditFinding) -> Optional[PolicyRule]:
    for rule in RULES:
        if _matches_rule(finding, rule):
            return rule
    return None
