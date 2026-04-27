"""Bounded, file-specific Devin prompts keyed by canonical ticket id.

Every prompt is deliberately narrow: it names the exact file(s), the vulnerability class,
the required behavior change, and the test scope. Devin should not have to explore the
repo to figure out intent. Prompts were reviewed alongside the curated portfolio in
`vulnerabilities.md` in the parent project memory.
"""

YAML_001 = """\
Repository: sevensyeds/superset (a fork of apache/superset).

Vulnerability: CWE-502 — Unsafe YAML deserialization via yaml.load with the default
Loader in the examples import tooling.

Target file: `superset/examples/utils.py` (look for `yaml.load(contents, Loader=yaml.Loader)`).

Required change:
1. Replace `yaml.load(..., Loader=yaml.Loader)` with `yaml.safe_load(...)`.
2. If the call uses `Loader=yaml.FullLoader` anywhere in that file, also switch it to `yaml.safe_load`.
3. Keep the function signature and return value identical — only the parsing call changes.
4. Do NOT introduce new dependencies.

Testing:
- Run the targeted pytest module(s) for examples import if they exist locally, or at minimum
  run `python -c "import superset.examples.utils"` to confirm the module still imports.
- If you cannot run full tests in the VM, explain exactly why in `test_results_summary`.

Constraints:
- Branch from `main`. Name the branch `fix/yaml-safe-load-examples`.
- Open a PR with title `fix(examples): use yaml.safe_load for example bundle import (CWE-502)`.
- PR body: explain the vuln in one short paragraph; note that `safe_load` only constructs basic
  Python objects, which is sufficient for the example YAML schema.
- PR body MUST include the line `Closes #{issue_number}` so GitHub auto-links the PR to the
  originating tracking issue.

Return the structured output. Be honest about confidence and backward-compat risk.
"""

MD5_001 = """\
Repository: sevensyeds/superset (a fork of apache/superset).

Vulnerability: CWE-327 — Use of a broken cryptographic hash (MD5) in hashing utilities.

Target files:
- `superset/utils/hashing.py` — contains `_HASH_FUNCTIONS` mapping (md5, sha256).
- `superset/config.py` — contains `HASH_ALGORITHM` default.

Context before you change anything: MD5 is wired in because existing deployments may have
stored MD5-based hashes. This is a COMPATIBILITY-aware hardening, NOT a removal.

Required change:
1. Emit a runtime `DeprecationWarning` with category `DeprecationWarning` the first time an MD5
   hash is requested via the hashing helpers. Use `warnings.warn(..., DeprecationWarning, stacklevel=2)`.
2. Update the docstring for the public hashing function(s) to clearly document that MD5 is
   retained for backward compatibility, is deprecated, and new code should default to SHA-256.
3. Do NOT delete the MD5 branch. Do NOT change the default HASH_ALGORITHM if it would break
   existing users (if it is already `sha256`, leave it; if it is `md5`, leave it but mention the
   deprecation in a comment nearby).
4. Make sure the warning fires once per process, not on every call. A module-level flag is fine.

Testing:
- Run the existing hashing tests if present. At minimum, confirm a quick round-trip:
  `python -c "from superset.utils.hashing import md5_sha_from_str; md5_sha_from_str('x')"` style
  (use whatever the real function is).
- Confirm the DeprecationWarning is emitted once with `python -W error::DeprecationWarning` style check.

Constraints:
- Branch from `main`. Name the branch `chore/md5-deprecation-warning`.
- PR title: `chore(crypto): deprecate MD5 hashing with runtime warning (CWE-327)`.
- PR body: explain that this is a compatibility-preserving hardening — it surfaces the risk
  without breaking deployments that persist MD5-derived values.
- PR body MUST include the line `Closes #{issue_number}` so GitHub auto-links the PR to the
  originating tracking issue.

Return the structured output. If you find you must modify more files than expected, explain in
`recommended_follow_up` and set `needs_human_review: true`.
"""

PICKLE_001 = """\
Repository: sevensyeds/superset (a fork of apache/superset).

Vulnerability: CWE-502 — Unsafe default deserialization codec in the metastore cache.

Target file: `superset/extensions/metastore_cache.py`.

Specific line of interest (look for this exact pattern):
`codec = config.get("CODEC") or PickleKeyValueCodec()`

Context before you change anything:
- `PickleKeyValueCodec` uses pickle, which is unsafe for any attacker-influenced payload.
- Maintainers already opt out in their own `config.py` (search for `JsonKeyValueCodec` —
  they explicitly override in the default configs around lines 1134 and 1148).
- The fix is to make the FALLBACK default safe: if the operator did not configure a codec,
  use JSON, not pickle. Operators who explicitly pass `PickleKeyValueCodec` still get pickle.

Required change:
1. In `metastore_cache.py`, change the fallback from `PickleKeyValueCodec()` to
   `JsonKeyValueCodec()`.
2. Add a short docstring/comment above the codec line explaining that the fallback is JSON for
   safety, and pickle remains available for operators who explicitly opt in.
3. Import `JsonKeyValueCodec` from wherever `PickleKeyValueCodec` is imported (same module).
4. Do NOT redesign the codec system, do NOT introduce a restricted unpickler, do NOT touch
   operator-opt-in paths.

Testing:
- Run the metastore cache tests. These likely assume pickle today — if tests fail because
  they serialize non-JSON-safe objects, DO NOT change the tests to force the fix through.
  Instead, set `needs_human_review: true`, explain the incompatibility in `test_results_summary`,
  and set `backward_compatibility_risk` to `medium` or `high`.
- If tests pass, this is a clean safe-by-default flip.

Constraints:
- Branch from `main`. Name the branch `fix/metastore-cache-default-json-codec`.
- PR title: `fix(cache): default metastore cache codec to JSON instead of pickle (CWE-502)`.
- PR body: frame as "safe-by-default flip, not a codec redesign". Note that operators who
  explicitly configure `PickleKeyValueCodec` are unaffected.
- PR body MUST include the line `Closes #{issue_number}` so GitHub auto-links the PR to the
  originating tracking issue.

Return the structured output. This one has real compat surface — be honest.
"""

PROMPTS = {
    "YAML-001": YAML_001,
    "MD5-001": MD5_001,
    "PICKLE-001": PICKLE_001,
}


def prompt_for(canonical_name: str, issue_number: int) -> str:
    """Render the bounded prompt for a canonical ticket, threading the GitHub issue number.

    The rendered prompt instructs Devin to include `Closes #{issue_number}` in the PR body so
    GitHub auto-links the PR to the tracking issue. Without this, the issue↔PR linkage lives
    only in our poller comment stream.
    """
    if canonical_name not in PROMPTS:
        raise KeyError(f"No bounded prompt registered for canonical ticket {canonical_name}")
    return PROMPTS[canonical_name].format(issue_number=issue_number)
