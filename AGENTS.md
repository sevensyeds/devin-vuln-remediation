# devin-vuln-remediation — Agent Notes

Dockerized orchestration service that scans Apache Superset for security findings, routes eligible ones through Devin, and surfaces progress back on GitHub. See the sibling `superset-master` project's memory for full context (architecture, vulnerabilities, Devin API, execution plan, collaboration notes).

## Framing

This is a **remediation control plane**, not a Bandit wrapper. The value sits in the layers between scanner findings and merged PRs: policy, curation, dedupe, Devin orchestration with guardrails, and GitHub-first observability.

## Stack

Python 3.11, FastAPI, APScheduler (in-process), SQLite, httpx, Bandit, Docker. No frontend. GitHub issue comments are the primary observability surface; `GET /status` JSON is secondary.

## Directory Map

```
app/
├── main.py              FastAPI app, endpoints, scheduler lifespan
├── config.py            pydantic-settings from env
├── database.py          SQLite schema: tickets, sessions, events
├── scanner.py           Bandit subprocess runner + JSON parser
├── policy.py            Raw Bandit → canonical ticket mapper + eligibility
├── github_client.py     find_issue_by_marker, create_issue, add_comment, close_issue
├── devin_client.py      create_session, get_session, send_message (stub)
├── orchestrator.py      scan → curate → dedupe → issue → session → persist
├── poller.py            Background poller (every 10s) on non-terminal sessions
├── status_model.py      Canonical status enum + Devin→canonical mapper
├── prompts.py           Bounded prompts keyed by canonical ticket id
├── structured_output.py Pydantic schema for Devin's structured_output_schema
└── status_endpoint.py   /status rollup aggregator
tests/
├── test_policy.py
├── test_orchestrator.py
└── mocks/               canned Devin responses
```

## Canonical Tickets

| ID | File | Fix |
|---|---|---|
| YAML-001 | `superset/examples/utils.py` | `yaml.load(..., Loader=yaml.Loader)` → `yaml.safe_load(...)` |
| MD5-001 | `superset/utils/hashing.py` + `superset/config.py` | Compat-aware: runtime deprecation warning + docstring; keep MD5 branch for backward compat |
| PICKLE-001 | `superset/extensions/metastore_cache.py:58` | `codec = config.get("CODEC") or PickleKeyValueCodec()` → `... or JsonKeyValueCodec()` |

Rejected (verified false positives in the Superset source): XSS via `Markup()` in `connectors/sqla/models.py`, `dashboard.py`, `slice.py`, `helpers.py`. Inputs are either already `escape()`'d, sanitized by regex, URL-encoded, or not user-controlled.

## Devin Primitives We Use

`repos`, `tags`, `advanced_mode: "improve"`, `structured_output_schema`, `max_acu_limit`. Playbooks, knowledge notes, and the messages endpoint are stretch only.

## Non-Goals

- No React/HTML dashboard.
- No webhook receiver (scheduler is the real trigger; `POST /scan` uses the same code path as a demo hook).
- No multi-repo fanout.
- No approval UI (merge is the approval).
- No separate cron container.

## Gotchas

- GitHub issues in the fork are numbered: #1 XSS (closed with evidence), #2 YAML, #3 MD5, #4 Pickle. Idempotent lookup uses a hidden HTML marker `<!-- canonical:<TICKET-ID> -->` in the issue body.
- The pickle bug is **not** an unrestricted-unpickler problem. It's a safe-by-default fallback flip. Maintainers already opt out in `config.py:1134,1148`.
- MD5 is a compatibility story, not a removal story — existing deployments may have stored hashes.
- YAML risk is lateral (admin-invoked example import), not open-internet RCE. Don't overclaim.
