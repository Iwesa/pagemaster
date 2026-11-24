"""Dependency failures (503 + Retry-After), liveness vs readiness (task 23, Req 7.1, 7.4, 7.5)."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from typing import Any
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import pytest
import redis.exceptions as redis_exc
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.app.api.routes import AppServices
from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.africastalking_client import AfricasTalkingSettings
from backend.app.services.health_state import HealthState
from backend.app.services.lifecycle import Lifecycle
from backend.app.services.readiness import ReaperHeartbeat

LEAK = "hunter2"
ALERT = {"service_name": "auth-db", "error_code": "DB_POOL_EXHAUSTED", "summary": "pool at 100%"}
WH_SECRET = "wh-secret"
ONCALL = "+254711000111"
SHORTCODE = "20880"
SMS_PATH = "/webhooks/africastalking/sms"

DEPENDENCY_ERRORS: list[Exception] = [
    asyncpg.PostgresConnectionError(f"password={LEAK}"),
    asyncpg.InterfaceError(f"pool is closed {LEAK}"),
    ConnectionRefusedError(f"redis://:{LEAK}@host refused"),
    OSError(f"network {LEAK}"),
    TimeoutError(f"pool acquire {LEAK}"),
    asyncio.TimeoutError(),
    redis_exc.ConnectionError(f"redis://:{LEAK}@host"),
    redis_exc.TimeoutError(f"slow {LEAK}"),
]


class Flaky:
    """Wraps a real in-memory adapter; the named methods raise ``exc`` while ``exc`` is set."""

    def __init__(self, inner: Any, methods: set[str]) -> None:
        self._inner = inner
        self._methods = methods
        self.exc: Exception | None = None

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._inner, name)
        if name not in self._methods:
            return target

        async def call(*args: Any, **kwargs: Any) -> Any:
            if self.exc is not None:
                raise self.exc
            return await target(*args, **kwargs)

        return call


def _base() -> AppServices:
    at = AfricasTalkingSettings(webhook_secret=SecretStr(WH_SECRET), to_number=ONCALL, shortcode=SHORTCODE)
    return build_in_memory_services(Settings(use_in_memory=True, africastalking=at))


def _client(services: AppServices, **overrides: Any) -> TestClient:
    return TestClient(create_app(services, Settings(frontend_dir=None, **overrides)))


def _assert_503(resp: Any) -> None:
    assert resp.status_code == 503
    assert resp.headers["Retry-After"] == "5"
    assert resp.json() == {"detail": "dependency unavailable"}
    assert LEAK not in resp.text


def _incident_count(services: AppServices) -> int:
    return len(asyncio.run(services.incidents.list_recent()))


# ---------------------------------------------------------------------------
# 503 mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("exc", DEPENDENCY_ERRORS, ids=lambda e: type(e).__name__)
def test_dedup_acquire_failure_is_503_and_creates_nothing(exc: Exception) -> None:
    base = _base()
    dedup = Flaky(base.dedup, {"acquire"})
    dedup.exc = exc
    services = dataclasses.replace(base, dedup=dedup)  # type: ignore[arg-type]
    with _client(services) as c:
        _assert_503(c.post("/webhooks/alerts", json=ALERT))
        assert _incident_count(services) == 0


def test_repository_failure_after_lock_releases_lock_and_leaves_no_incident() -> None:
    base = _base()
    repo = Flaky(base.incidents, {"create"})
    repo.exc = asyncpg.InterfaceError(f"connection is closed {LEAK}")
    services = dataclasses.replace(base, incidents=repo)  # type: ignore[arg-type]
    with _client(services) as c:
        _assert_503(c.post("/webhooks/alerts", json=ALERT))
        assert _incident_count(services) == 0
        repo.exc = None  # lock was released: the same alert is a new incident, not a duplicate
        resp = c.post("/webhooks/alerts", json=ALERT)
        assert resp.status_code == 202


def test_lock_release_failure_does_not_mask_the_503() -> None:
    base = _base()
    repo = Flaky(base.incidents, {"create"})
    repo.exc = asyncpg.InterfaceError("closed")
    dedup = Flaky(base.dedup, {"release"})
    dedup.exc = redis_exc.ConnectionError(LEAK)
    services = dataclasses.replace(base, incidents=repo, dedup=dedup)  # type: ignore[arg-type]
    with _client(services) as c:
        _assert_503(c.post("/webhooks/alerts", json=ALERT))


def test_failure_after_incident_row_marks_it_failed_not_triaging() -> None:
    base = _base()
    audit = Flaky(base.audit, {"records"})  # reads the chain after the row and first audit exist
    audit.exc = asyncpg.PostgresConnectionError(LEAK)
    services = dataclasses.replace(base, audit=audit)  # type: ignore[arg-type]
    with _client(services) as c:
        _assert_503(c.post("/webhooks/alerts", json=ALERT))
        states = {r.state for r in asyncio.run(services.incidents.list_recent())}
        assert states <= {"FAILED"}
        audit.exc = None
        assert c.post("/webhooks/alerts", json=ALERT).status_code == 202


def test_reply_path_failure_is_503_and_message_id_can_be_redelivered() -> None:
    base = _base()
    repo = Flaky(base.incidents, {"expire_if_stale"})
    services = dataclasses.replace(base, incidents=repo)  # type: ignore[arg-type]
    with _client(services) as c:
        incident_id = c.post("/webhooks/alerts", json=ALERT).json()["incident_id"]
        record = asyncio.run(base.incidents.get(UUID(incident_id)))
        assert record is not None
        form = {"from": ONCALL, "to": SHORTCODE, "text": f"{record.token}-1", "id": "ATXid_redeliver"}
        headers = {"X-Webhook-Secret": WH_SECRET}
        repo.exc = redis_exc.ConnectionError(LEAK)
        _assert_503(c.post(SMS_PATH, data=form, headers=headers))
        repo.exc = None
        redelivered = c.post(SMS_PATH, data=form, headers=headers)
        assert redelivered.status_code == 200 and redelivered.json() == {"status": "ok"}


def test_seen_id_store_failure_is_503() -> None:
    base = _base()
    seen = Flaky(base.seen_ids, {"claim"})
    seen.exc = redis_exc.ConnectionError(LEAK)
    services = dataclasses.replace(base, seen_ids=seen)  # type: ignore[arg-type]
    with _client(services) as c:
        form = {"from": ONCALL, "to": SHORTCODE, "text": "AB-1", "id": "ATXid_1"}
        _assert_503(c.post(SMS_PATH, data=form, headers={"X-Webhook-Secret": WH_SECRET}))


def test_unrelated_errors_are_not_mapped() -> None:
    base = _base()
    dedup = Flaky(base.dedup, {"acquire"})
    dedup.exc = ValueError("bug")
    services = dataclasses.replace(base, dedup=dedup)  # type: ignore[arg-type]
    app = create_app(services, Settings(frontend_dir=None))
    with TestClient(app, raise_server_exceptions=False) as c:
        assert c.post("/webhooks/alerts", json=ALERT).status_code == 500


# ---------------------------------------------------------------------------
# Once-per-outage logging and recovery without restart
# ---------------------------------------------------------------------------


def _outage_records(caplog: pytest.LogCaptureFixture, marker: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if marker in r.getMessage()]


def test_outage_logged_once_and_service_recovers_on_same_app(caplog: pytest.LogCaptureFixture) -> None:
    base = _base()
    dedup = Flaky(base.dedup, {"acquire"})
    services = dataclasses.replace(base, dedup=dedup)  # type: ignore[arg-type]
    caplog.set_level(logging.INFO)
    with _client(services) as c:
        dedup.exc = redis_exc.ConnectionError(f"redis://:{LEAK}@host")
        for _ in range(5):
            _assert_503(c.post("/webhooks/alerts", json=ALERT))
        assert len(_outage_records(caplog, "outage started")) == 1
        dedup.exc = None
        assert c.post("/webhooks/alerts", json=ALERT).status_code == 202  # no restart
        assert len(_outage_records(caplog, "outage ended")) == 1
        dedup.exc = redis_exc.TimeoutError(LEAK)  # a second outage logs again
        _assert_503(c.post("/webhooks/alerts", json={**ALERT, "error_code": "OTHER"}))
        assert len(_outage_records(caplog, "outage started")) == 2
    assert LEAK not in caplog.text


def test_readyz_recovery_ends_the_outage(caplog: pytest.LogCaptureFixture) -> None:
    base = _base()
    dedup = Flaky(base.dedup, {"acquire"})
    dedup.exc = OSError("down")
    services = dataclasses.replace(base, dedup=dedup)  # type: ignore[arg-type]
    caplog.set_level(logging.INFO)
    with _client(services) as c:
        _assert_503(c.post("/webhooks/alerts", json=ALERT))
        assert services.outages.active
        assert c.get("/readyz").status_code == 200
        assert not services.outages.active


# ---------------------------------------------------------------------------
# /healthz and /readyz
# ---------------------------------------------------------------------------


async def _ok() -> None:
    return None


def _boom(exc: Exception) -> Any:
    async def raiser() -> None:
        raise exc

    return raiser


def test_readyz_in_memory_mode() -> None:
    with _client(_base(), dry_run=True) as c:
        resp = c.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "dry_run": True,
        "channel": "africastalking",
        "checks": {
            "postgres": {"ok": True, "mode": "in_memory"},
            "redis": {"ok": True, "mode": "in_memory"},
            "reaper": {"ok": True},
            "pager": {"ok": True, "consecutive_failures": 0},
        },
    }


def test_readyz_reports_each_check_without_leaking_text() -> None:
    services = dataclasses.replace(
        _base(), ping_postgres=_ok, ping_redis=_boom(redis_exc.ConnectionError(f"redis://:{LEAK}@h"))
    )
    with _client(services) as c:
        resp = c.get("/readyz")
        live = c.get("/healthz")
    body = resp.json()
    assert resp.status_code == 503 and body["status"] == "unavailable"
    assert body["checks"]["postgres"] == {"ok": True}
    assert body["checks"]["redis"] == {"ok": False}
    assert LEAK not in resp.text
    assert live.status_code == 200 and live.json() == {"status": "ok"}  # liveness ignores dependencies


def test_readyz_postgres_failure() -> None:
    services = dataclasses.replace(_base(), ping_postgres=_boom(asyncpg.InterfaceError(LEAK)), ping_redis=_ok)
    with _client(services) as c:
        body = c.get("/readyz").json()
    assert body["checks"]["postgres"]["ok"] is False and body["checks"]["redis"]["ok"] is True


def test_readyz_pager_threshold_default_and_custom() -> None:
    base = _base()
    with _client(base) as c:
        base.health.record_page_failure()
        base.health.record_page_failure()
        assert c.get("/readyz").status_code == 200
        base.health.record_page_failure()
        resp = c.get("/readyz")
        assert resp.status_code == 503
        assert resp.json()["checks"]["pager"] == {"ok": False, "consecutive_failures": 3}
        base.health.record_page_success()
        assert c.get("/readyz").status_code == 200
    strict = dataclasses.replace(_base(), page_failure_ready_threshold=1, health=HealthState())
    with _client(strict) as c:
        strict.health.record_page_failure()
        assert c.get("/readyz").status_code == 503


def test_readyz_reaper_dead_when_heartbeat_is_stale() -> None:
    now = [100.0]
    beat = ReaperHeartbeat(clock=lambda: now[0])
    services = dataclasses.replace(_base(), reaper=beat)
    with _client(services) as c:
        # the lifespan configured the reaper with the default 30 s interval
        assert c.get("/readyz").json()["checks"]["reaper"] == {"ok": True}
        now[0] += 3 * 30 + 1
        resp = c.get("/readyz")
        assert resp.status_code == 503 and resp.json()["checks"]["reaper"]["ok"] is False
        beat.beat()
        assert c.get("/readyz").status_code == 200


def test_reaper_heartbeat_not_applicable_without_reaper() -> None:
    assert ReaperHeartbeat().alive()


async def test_run_reaper_beats_each_iteration() -> None:
    base = _base()
    beat = ReaperHeartbeat()
    beat.configure(0.01)
    first = beat.last_tick_at
    lifecycle: Lifecycle = dataclasses.replace(base.lifecycle, heartbeat=beat)
    task = asyncio.create_task(lifecycle.run_reaper(0.01))
    await asyncio.sleep(0.1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert first is not None and beat.last_tick_at is not None and beat.last_tick_at > first


def test_hung_dependency_cannot_hang_the_probe() -> None:
    async def hang() -> None:
        await asyncio.sleep(3600)

    services = dataclasses.replace(_base(), ping_postgres=hang, ping_redis=hang)
    with _client(services) as c:
        started = time.monotonic()
        resp = c.get("/readyz")
        elapsed = time.monotonic() - started
    assert resp.status_code == 503
    assert resp.json()["checks"]["postgres"]["ok"] is False
    assert elapsed < 4.0  # both probes run concurrently within one 2 s timeout


def test_unwired_services_are_not_ready() -> None:
    app = create_app(None, Settings(use_in_memory=True, frontend_dir=None))
    with TestClient(app) as c:  # lifespan wires in-memory services
        assert c.get("/readyz").status_code == 200
    # outside the lifespan nothing is wired yet
    cold = TestClient(create_app(None, Settings(use_in_memory=True, frontend_dir=None)))
    assert cold.get("/healthz").status_code == 200
    resp = cold.get("/readyz")
    assert resp.status_code == 503 and resp.json()["status"] == "unavailable"


def test_page_failure_threshold_setting() -> None:
    assert Settings.from_env({}).page_failure_ready_threshold == 3
    assert Settings.from_env({"PAGE_FAILURE_READY_THRESHOLD": "5"}).page_failure_ready_threshold == 5
    assert Settings.from_env({"PAGE_FAILURE_READY_THRESHOLD": "0"}).page_failure_ready_threshold == 1
    assert Settings.from_env({"PAGE_FAILURE_READY_THRESHOLD": "x"}).page_failure_ready_threshold == 3
