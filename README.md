# devin-vuln-remediation

A Dockerized remediation control plane that scans Apache Superset for eligible security findings, opens GitHub issues, launches Devin sessions with policy and budget guardrails, and surfaces progress and outcomes back in GitHub and a `/status` JSON rollup.

Built against [`sevensyeds/superset`](https://github.com/sevensyeds/superset), a fork of [`apache/superset`](https://github.com/apache/superset).

---

## What this is (and what it isn't)

This is a **remediation control plane**, not a Bandit wrapper. The value is in the layers between scanner findings and merged PRs:

- a policy/curation layer that maps raw findings to a small number of canonical remediation tickets
- eligibility tagging (auto-remediate vs review-required)
- Devin orchestration with structured output, ACU budgets, and concurrency caps
- GitHub issues + comments as the primary observability surface
- a compact `/status` JSON rollup for dashboards / CI

Not "zero engineer time." The accurate claim is **near-zero toil from finding to PR — engineers review fixes instead of filing and shepherding tickets.**

## Flow

```
[APScheduler tick]   or   [POST /scan]
                │
                ▼
       Bandit -r superset/ -f json
                │
                ▼
 Policy / curation → canonical tickets (YAML-001 / MD5-001 / PICKLE-001)
                │
                ▼
 GitHub: create or reuse issue (idempotent via hidden canonical marker)
                │
                ▼
 Devin session: repos + tags + advanced_mode:"improve"
                + structured_output_schema + max_acu_limit
                │
                ▼
 Poller (every 10s) → Devin status → canonical status → GitHub comment
                │
                ▼
 Terminal: PR URL, ACUs, structured_output → /status rollup
```

## Canonical portfolio

| ID | CWE | Target file | Fix | Eligibility |
|---|---|---|---|---|
| `YAML-001` | 502 | `superset/examples/utils.py` | `yaml.load(..., Loader=yaml.Loader)` → `yaml.safe_load(...)` | auto_remediate |
| `MD5-001` | 327 | `superset/utils/hashing.py` + `config.py` | Runtime `DeprecationWarning` + docstring; MD5 branch retained for back-compat | auto_remediate |
| `PICKLE-001` | 502 | `superset/extensions/metastore_cache.py` | Flip fallback codec: `PickleKeyValueCodec()` → `JsonKeyValueCodec()` | auto_remediate, gated by structured output |

A fourth Bandit candidate (XSS via `Markup()`) was investigated and rejected — inputs are already `escape()`'d, regex-sanitized, URL-encoded, or not user-controlled. Issue #1 in the fork was closed with evidence; the investigation is part of the story.

## Canonical status model

Devin's raw statuses are mapped into a smaller vocabulary so GitHub comments, the `/status` JSON, and the narration all speak one language:

`detected → deduped → issue_opened → session_started → running → pr_opened → succeeded | needs_human_review | failed`

`needs_human_review` is a first-class terminal outcome: if Devin returns `needs_human_review: true` or `backward_compatibility_risk: high` in its structured output, the PR is still open but the canonical status reflects the uncertainty.

## Devin primitives used

- `repos` — scopes the session to the Superset fork
- `tags` — `[canonical_name, cwe, severity]` for filtering in the Devin dashboard
- `advanced_mode: "improve"` — signals this is a fix task, not greenfield
- `structured_output_schema` — forces machine-readable remediation metadata (see `app/structured_output.py`)
- `max_acu_limit` — per-session budget cap (default 10)

Stretch (not wired in v1): `playbook_id`, `knowledge_ids`, messages endpoint.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness + mock-mode flag |
| GET | `/status` | Compact JSON rollup of canonical tickets, PR URLs, ACUs, mean time to terminal |
| GET | `/sessions` | Detailed session rows with parsed structured output |
| POST | `/scan` | Manual trigger — **same codepath** as the scheduler. For demos and urgent re-runs |

No frontend, no webhook receiver, no multi-repo fanout.

## Running it

### Prerequisites

1. A checkout of [`sevensyeds/superset`](https://github.com/sevensyeds/superset) next to this repo (or adjust `SUPERSET_LOCAL_PATH`).
2. A Devin service-user API key (Devin dashboard → Settings → Service Users → Provision). Starts with `cog_`.
3. A GitHub personal access token with `repo` scope for the fork.

### Configure

```bash
cp .env.example .env
# fill in DEVIN_API_KEY, DEVIN_ORG_ID, GITHUB_TOKEN
```

Key env vars (full list in `.env.example`):

| Var | Default | Purpose |
|---|---|---|
| `DEVIN_API_KEY` | — | Service user API key (`cog_…`) |
| `DEVIN_ORG_ID` | — | Devin org id |
| `GITHUB_TOKEN` | — | PAT with repo scope for the fork |
| `GITHUB_REPO` | `sevensyeds/superset` | Target repo |
| `SCAN_CRON` | `*/10 * * * *` | Scheduler cron (demo default) |
| `MAX_CONCURRENT_SESSIONS` | `2` | Hard cap on active Devin sessions |
| `MAX_ACU_PER_SESSION` | `10` | Per-session budget cap |
| `MOCK_DEVIN` | `false` | When true, serves canned responses from `tests/mocks/` |

### Start

```bash
docker compose up --build
```

Health check:

```bash
curl -s localhost:8000/health
# {"ok": true, "mock_devin": false}
```

Trigger a scan manually (same codepath as the scheduler):

```bash
curl -s -X POST localhost:8000/scan | jq
```

Watch progress in the fork's Issues tab and via:

```bash
curl -s localhost:8000/status | jq
```

### Dry-run with mock Devin

For demos or local rehearsals without consuming real ACUs:

```bash
MOCK_DEVIN=true docker compose up --build
curl -s -X POST localhost:8000/scan
# After ~30s of polling, /status shows YAML-001 + MD5-001 succeeded,
# PICKLE-001 needs_human_review.
```

## Guardrails

- **Concurrency:** max 2 in-flight Devin sessions (env-configurable).
- **Per-session budget:** `max_acu_limit=10` passed to Devin; surfaced in GitHub comments and `/status`.
- **Wall-clock timeout:** sessions exceeding `SESSION_MAX_WALL_CLOCK_SECONDS` (default 1h) are marked failed.
- **Idempotency (two layers):** within a single scan, `policy.curate()` collapses multiple Bandit findings of the same rule (e.g. `pickle.loads` + `pickle.dumps` on adjacent lines in the same file) into one canonical ticket — keyed by `canonical_name`, since the bounded Devin prompt is identical. Across scans, each ticket carries a deterministic `canonical_id` of the form `<TICKET>-<code_fingerprint>`; GitHub issues store this in a hidden `<!-- canonical:<id> -->` body marker so rescanning matches and reuses the existing issue instead of opening duplicates.
- **Eligibility gating:** only tickets in the curated portfolio reach Devin. Raw Bandit hits that don't match a policy rule are dropped.

## Testing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
python -m pytest -v
```

Tests cover (5 modules, 28 tests):
- **`test_policy.py`** — curation produces the right three canonical tickets, noise/unmatched findings dropped, deterministic `canonical_id`s, within-scan dedupe by `canonical_name`.
- **`test_status_model.py`** — full canonical-status mapping including the `running + finished` and `suspended + inactivity` branches that took real-world tuning to get right (cost-cap suspend → FAILED; idle suspend with PR → evaluated like `exit`).
- **`test_poller.py`** — wall-clock timeout regression coverage: completed-but-stale sessions get evaluated by the mapper, only genuinely runaway ones get force-failed.
- **`test_devin_client.py`** — Devin API contract: `create_session` POST URL + body shape, `structured_output_schema` required fields, `Closes #N` prompt threading in bounded prompts, and `get_session` URL shape.
- **`test_orchestrator.py`** — end-to-end pipeline under mock Devin: idempotency on rescan, YAML + MD5 land SUCCEEDED, PICKLE lands NEEDS_HUMAN_REVIEW.

## Project layout

```
app/
├── main.py              FastAPI app, endpoints, scheduler lifespan
├── config.py            pydantic-settings from env
├── database.py          SQLite schema: tickets, sessions, events, scans
├── scanner.py           Bandit subprocess runner + JSON parser
├── policy.py            Raw Bandit → canonical ticket mapper + eligibility
├── github_client.py     find_issue_by_marker, create_issue, add_comment, close_issue
├── devin_client.py      create_session, get_session, send_message (stub) + mock mode
├── orchestrator.py      scan → curate → dedupe → issue → session → persist
├── poller.py            10s polling loop on non-terminal sessions
├── status_model.py      Canonical status enum + Devin→canonical mapper
├── prompts.py           Bounded prompts keyed by canonical ticket id
├── structured_output.py Pydantic schema → Devin's structured_output_schema
└── status_endpoint.py   /status and /sessions aggregators
tests/
├── test_policy.py
├── test_status_model.py
├── test_poller.py
├── test_devin_client.py
├── test_orchestrator.py
└── mocks/
    ├── bandit_sample.json
    ├── session_running.json
    ├── session_finished.json
    ├── session_needs_review.json
    └── session_error.json
```

## What's next

- Plug in real SAST/SCA feeds (Semgrep, Snyk) alongside Bandit
- Multi-repo fanout
- Wire the messages endpoint to nudge sessions stuck in `waiting_for_user`
- Devin knowledge notes + playbooks for repo-specific remediation patterns
- CI gate on `/status` rollup metrics
