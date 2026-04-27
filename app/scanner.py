import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional

from app.config import settings

log = logging.getLogger(__name__)


@dataclass
class BanditFinding:
    test_id: str          # e.g. "B506"
    test_name: str        # e.g. "yaml_load"
    severity: str         # LOW / MEDIUM / HIGH
    confidence: str       # LOW / MEDIUM / HIGH
    filename: str         # absolute or workspace-relative path
    line_number: int
    code: str             # offending snippet from bandit
    cwe: Optional[str]    # e.g. "502" if bandit reports it

    @classmethod
    def from_bandit_result(cls, item: dict) -> "BanditFinding":
        cwe_raw = item.get("issue_cwe") or {}
        cwe_id = cwe_raw.get("id") if isinstance(cwe_raw, dict) else None
        return cls(
            test_id=item.get("test_id", ""),
            test_name=item.get("test_name", ""),
            severity=item.get("issue_severity", "LOW"),
            confidence=item.get("issue_confidence", "LOW"),
            filename=item.get("filename", ""),
            line_number=item.get("line_number", 0),
            code=item.get("code", ""),
            cwe=str(cwe_id) if cwe_id is not None else None,
        )


def run_bandit(
    target_path: Optional[str] = None,
    tests: Optional[list[str]] = None,
) -> list[BanditFinding]:
    """Run Bandit as a subprocess against the configured Superset checkout.

    Narrow the scan to tests we actually remediate on (S506/S324/S301) for demo speed.
    Parses JSON; non-zero exit from Bandit is expected when findings exist, so we only
    fail on a parse error or a subprocess-level failure.
    """
    path = target_path or settings.superset_path
    cmd = ["bandit", "-r", path, "-f", "json", "-q"]
    if tests:
        cmd.extend(["-t", ",".join(tests)])

    log.info("running bandit: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

    # Bandit exits 1 when issues found; stdout still has JSON. Exit >1 = real error.
    if proc.returncode > 1 and not proc.stdout:
        raise RuntimeError(f"bandit failed: rc={proc.returncode} stderr={proc.stderr[:500]}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"bandit produced non-JSON output: {e}; stdout head: {proc.stdout[:300]}"
        ) from e

    results = payload.get("results", [])
    return [BanditFinding.from_bandit_result(r) for r in results]
