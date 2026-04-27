"""FastAPI application. Endpoints + scheduler wiring."""

import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool

from app.config import settings
from app.database import init_db
from app.orchestrator import run_scan
from app.poller import poll_once
from app.status_endpoint import sessions_list, status_rollup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("remediation")


def _parse_cron(expr: str) -> CronTrigger:
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError(f"SCAN_CRON must be a 5-field cron expression, got: {expr!r}")
    minute, hour, day, month, day_of_week = fields
    return CronTrigger(
        minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week
    )


async def _scheduled_scan() -> None:
    try:
        summary = await run_in_threadpool(run_scan)
        log.info("scheduled scan complete: %s", summary)
    except Exception:
        log.exception("scheduled scan failed")


async def _scheduled_poll() -> None:
    try:
        summary = await run_in_threadpool(poll_once)
        if summary["transitions"] or summary["terminated"]:
            log.info("poll tick: %s", summary)
    except Exception:
        log.exception("poll tick failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(_scheduled_scan, _parse_cron(settings.scan_cron), id="scan")
    scheduler.add_job(
        _scheduled_poll,
        "interval",
        seconds=settings.poll_interval_seconds,
        id="poll",
    )
    scheduler.start()
    log.info(
        "scheduler started: scan cron=%r, poll every %ss",
        settings.scan_cron,
        settings.poll_interval_seconds,
    )
    app.state.scheduler = scheduler
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="Devin Vulnerability Remediation Control Plane",
    description=(
        "Scans Apache Superset for eligible security findings, opens GitHub issues, "
        "launches Devin sessions with policy + budget guardrails, and reports outcomes "
        "back to GitHub and a /status JSON rollup."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "mock_devin": settings.mock_devin}


@app.get("/status")
def status() -> dict:
    return status_rollup()


@app.get("/sessions")
def sessions() -> list[dict]:
    return sessions_list()


@app.post("/scan")
async def trigger_scan() -> dict:
    """Manual trigger — same codepath as the scheduler.

    Use this for demos and for urgent re-runs. It is NOT the primary event source.
    """
    summary = await run_in_threadpool(run_scan)
    return summary
