"""Real-stack chaos tests (task 23 outage test, task 27 chaos variants).

Skipped unless the environment names real servers. Run them locally with::

    docker compose up -d postgres redis
    export TEST_DATABASE_URL=postgresql://pagemaster:pagemaster_dev@127.0.0.1:5432/postgres
    export TEST_REDIS_URL=redis://:pagemaster_redis_dev@127.0.0.1:6379/0
    pytest backend/tests/test_real_stack.py -v

(PowerShell: ``$env:TEST_DATABASE_URL = "..."``.) ``TEST_DATABASE_URL`` must belong to a role that may
``CREATE DATABASE``: every test gets a scratch database (``pm_chaos_<random>``, schema plus demo seed)
and drops it afterwards. The compose ports are published on 127.0.0.1 only.

What runs where:

* ``test_redis_outage_returns_503_then_recovers_without_restart`` needs ``TEST_REDIS_URL`` only. The app
  runs in-process with in-memory adapters, and its dedup store is switched to a closed port and back.
* The chaos tests below need both variables. They start the real application (``uvicorn``, production
  wiring, ``USE_IN_MEMORY=false``, ``DRY_RUN=true``, ``MCP_TRANSPORT=inprocess``) as a subprocess through
  ``backend/tests/chaos_server.py``:

  - crash recovery: an alert is posted while triage hangs, the process is killed (SIGKILL, or
    ``TerminateProcess`` on Windows), a new process starts on the same database and Redis, and the
    reaper (``TRIAGE_TIMEOUT_SECONDS=10``, ``REAPER_INTERVAL_SECONDS=1``) must move the incident out of
    ``TRIAGING`` (``FAILED``, or resumed from its checkpoint). A re-fired alert then returns 202.
  - 60-alert storm: all accepted, no incident left in flight, at most ``PAGE_RATE_PER_MINUTE`` pages.
  - Postgres and Redis outage: the dependency is reached through a small TCP proxy owned by the test.
    Stopping the proxy cuts live connections and refuses new ones (what a stopped server does); the app
    must answer 503 with ``Retry-After`` and ``/readyz`` must name the dependency, then return to 202
    after the proxy is back, without restarting the app.

Two tests need no servers and always run: they check the subprocess harness and the proxy.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from pydantic import SecretStr
from redis.asyncio import Redis

from backend.app.main import Settings, build_in_memory_services, create_app
from backend.app.services.africastalking_client import AfricasTalkingSettings
from backend.app.services.dedup import DedupResult, RedisDedupStore

TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL")
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")

requires_redis = pytest.mark.skipif(not TEST_REDIS_URL, reason="TEST_REDIS_URL is not set")
requires_stack = pytest.mark.skipif(
    not (TEST_REDIS_URL and TEST_DATABASE_URL), reason="TEST_DATABASE_URL and TEST_REDIS_URL are not both set"
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_DIR = REPO_ROOT / "database"
CLOSED_PORT = 1  # nothing listens here: connection refused


def _closed_port_url(url: str) -> str:
    parts = urlsplit(url)
    auth = f"{parts.netloc.rpartition('@')[0]}@" if "@" in parts.netloc else ""
    return urlunsplit(parts._replace(netloc=f"{auth}127.0.0.1:{CLOSED_PORT}"))


class SwitchableDedup:
    """Delegates to the real or the unreachable Redis dedup store."""

    def __init__(self, real: RedisDedupStore, dead: RedisDedupStore) -> None:
        self.real = real
        self.dead = dead
        self.down = False

    @property
    def _active(self) -> RedisDedupStore:
        return self.dead if self.down else self.real

    async def acquire(self, service_name: str, error_code: str, incident_id: UUID) -> DedupResult:
        return await self._active.acquire(service_name, error_code, incident_id)

    async def release(self, service_name: str, error_code: str, incident_id: UUID) -> Any:
        return await self._active.release(service_name, error_code, incident_id)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._active, name)


@requires_redis
def test_redis_outage_returns_503_then_recovers_without_restart() -> None:
    assert TEST_REDIS_URL is not None
    real = Redis.from_url(TEST_REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
    dead = Redis.from_url(_closed_port_url(TEST_REDIS_URL), socket_connect_timeout=1, socket_timeout=1)
    dedup = SwitchableDedup(RedisDedupStore(real), RedisDedupStore(dead))

    async def ping_redis() -> None:
        await (dead if dedup.down else real).ping()

    at = AfricasTalkingSettings(webhook_secret=SecretStr("s"), to_number="+254711000111", shortcode="20880")
    base = build_in_memory_services(Settings(use_in_memory=True, africastalking=at))
    services = dataclasses.replace(base, dedup=dedup, ping_redis=ping_redis)  # type: ignore[arg-type]
    alert = {"service_name": "auth-db", "error_code": f"RS_{uuid4().hex[:8]}", "summary": "outage test"}

    with TestClient(create_app(services, Settings(frontend_dir=None))) as client:
        assert client.get("/readyz").json()["checks"]["redis"]["ok"] is True

        dedup.down = True
        resp = client.post("/webhooks/alerts", json=alert)
        assert resp.status_code == 503 and resp.headers["Retry-After"] == "5"
        assert resp.json() == {"detail": "dependency unavailable"}
        ready = client.get("/readyz")
        assert ready.status_code == 503 and ready.json()["checks"]["redis"]["ok"] is False
        assert client.get("/healthz").status_code == 200

        dedup.down = False
        resp = client.post("/webhooks/alerts", json=alert)
        assert resp.status_code == 202
        assert client.get("/readyz").status_code == 200


# ---------------------------------------------------------------------------
# Harness: application subprocess, TCP proxy, scratch database
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class AppProcess:
    """The production app under uvicorn in a child process (``backend.tests.chaos_server``)."""

    def __init__(self, env: dict[str, str]) -> None:
        self.port = _free_port()
        self.env = {**os.environ, **env, "PORT": str(self.port), "PYTHONUNBUFFERED": "1"}
        self.log = tempfile.TemporaryFile(mode="w+b")
        self.proc: subprocess.Popen[bytes] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "backend.tests.chaos_server"],
            cwd=REPO_ROOT,
            env=self.env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )

    def output(self) -> str:
        self.log.flush()
        self.log.seek(0)
        return self.log.read().decode("utf-8", errors="replace")[-3000:]

    async def wait_ready(self, timeout: float = 90.0) -> None:
        """Poll ``/readyz`` until 200. Fails fast, with the process output, if the child exits."""
        assert self.proc is not None
        deadline = time.monotonic() + timeout
        async with httpx.AsyncClient(base_url=self.url, timeout=3.0) as client:
            while time.monotonic() < deadline:
                assert self.proc.poll() is None, f"app exited early:\n{self.output()}"
                try:
                    if (await client.get("/readyz")).status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.3)
        raise AssertionError(f"app not ready after {timeout}s:\n{self.output()}")

    def kill(self) -> None:
        """SIGKILL (``TerminateProcess`` on Windows): no shutdown hooks, no cleanup."""
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=15)

    def stop(self) -> None:
        self.kill()
        self.log.close()


class TcpProxy:
    """Forwards 127.0.0.1:port to a target. ``stop`` resets live connections and refuses new ones."""

    def __init__(self, target_host: str, target_port: int) -> None:
        self.target = (target_host, target_port)
        self.port = 0
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)
        self.port = int(self._server.sockets[0].getsockname()[1])

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            up_reader, up_writer = await asyncio.open_connection(*self.target)
        except OSError:
            writer.transport.abort()
            return
        self._writers.update((writer, up_writer))

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while data := await src.read(65536):
                    dst.write(data)
                    await dst.drain()
            except OSError:
                pass
            finally:
                dst.close()

        try:
            await asyncio.gather(pump(reader, up_writer), pump(up_reader, writer))
        finally:
            self._writers.difference_update((writer, up_writer))

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        for writer in list(self._writers):
            writer.transport.abort()
        self._writers.clear()
        await asyncio.sleep(0.1)


def _with_hostport(url: str, host: str, port: int) -> str:
    parts = urlsplit(url)
    auth = f"{parts.netloc.rpartition('@')[0]}@" if "@" in parts.netloc else ""
    return urlunsplit(parts._replace(netloc=f"{auth}{host}:{port}"))


def _hostport(url: str, default_port: int) -> tuple[str, int]:
    parts = urlsplit(url)
    return parts.hostname or "127.0.0.1", parts.port or default_port


def _with_db(url: str, name: str) -> str:
    return urlunsplit(urlsplit(url)._replace(path=f"/{name}"))


@pytest_asyncio.fixture()
async def scratch_dsn() -> AsyncIterator[str]:
    """A throwaway database with ``10_schema.sql`` and ``30_demo_seed.sql`` applied."""
    assert TEST_DATABASE_URL is not None
    name = f"pm_chaos_{uuid4().hex[:12]}"
    admin = await asyncpg.connect(TEST_DATABASE_URL)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        scratch = await asyncpg.connect(_with_db(TEST_DATABASE_URL, name))
        try:
            for script in ("10_schema.sql", "30_demo_seed.sql"):
                await scratch.execute((DB_DIR / script).read_text(encoding="utf-8-sig"))
        finally:
            await scratch.close()
        yield _with_db(TEST_DATABASE_URL, name)
    finally:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


def _app_env(database_url: str, redis_url: str, **extra: str) -> dict[str, str]:
    """Production wiring with short lifecycle timeouts so recovery shows up in seconds."""
    env = {
        "USE_IN_MEMORY": "false",
        "DRY_RUN": "true",
        "MCP_TRANSPORT": "inprocess",
        "DATABASE_URL": database_url,
        "MCP_READER_DATABASE_URL": database_url,  # read-only is enforced per connection by the adapter
        "REDIS_URL": redis_url,
        "TRIAGE_TIMEOUT_SECONDS": "10",
        "EXECUTING_TIMEOUT_SECONDS": "10",
        "INFLIGHT_STALE_SECONDS": "10",
        "REAPER_INTERVAL_SECONDS": "1",
        "ALERT_WEBHOOK_SECRET": "",
        "API_READ_SECRET": "",
        "ONCALL_PHONE_NUMBER": "",
        "GEMINI_API_KEY": "",
        "OPENAI_API_KEY": "",
    }
    return {**env, **extra}


async def _incident(client: httpx.AsyncClient, incident_id: str) -> dict[str, Any]:
    rows = (await client.get("/api/incidents")).json()
    return next(r for r in rows if r["incident_id"] == incident_id)  # type: ignore[no-any-return]


async def _eventually(check: Callable[[], Awaitable[bool]], timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await check():
            return
        await asyncio.sleep(0.5)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


# ---------------------------------------------------------------------------
# Harness self-checks (no servers needed)
# ---------------------------------------------------------------------------


async def test_app_process_harness_starts_serves_is_killed_and_restarts() -> None:
    env = {"USE_IN_MEMORY": "true", "DRY_RUN": "true", "ALERT_WEBHOOK_SECRET": "", "ONCALL_PHONE_NUMBER": ""}
    first = AppProcess(env)
    try:
        first.start()
        await first.wait_ready()
        async with httpx.AsyncClient(base_url=first.url, timeout=5.0) as client:
            alert = {"service_name": "auth-db", "error_code": "HARNESS", "summary": "smoke"}
            assert (await client.post("/webhooks/alerts", json=alert)).status_code == 202
        first.kill()
        assert first.proc is not None and first.proc.poll() is not None
    finally:
        first.stop()
    second = AppProcess(env)
    try:
        second.start()
        await second.wait_ready()  # a fresh process on a fresh port
    finally:
        second.stop()


async def test_tcp_proxy_forwards_then_cuts_and_restores() -> None:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while data := await reader.read(1024):
            writer.write(data)
            await writer.drain()
        writer.close()

    backend = await asyncio.start_server(echo, "127.0.0.1", 0)
    proxy = TcpProxy("127.0.0.1", int(backend.sockets[0].getsockname()[1]))
    try:
        await proxy.start()
        port = proxy.port

        async def roundtrip() -> bytes:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"ping")
            await writer.drain()
            try:
                return await asyncio.wait_for(reader.readexactly(4), 2)
            finally:
                writer.close()

        assert await roundtrip() == b"ping"
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"ping")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(4), 2) == b"ping"  # proxied pipe is established
        await proxy.stop()
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):  # live connection was reset
            writer.write(b"x")
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(1), 2)
        with pytest.raises(OSError):  # and new ones are refused
            await asyncio.open_connection("127.0.0.1", port)
        await proxy.start()
        assert proxy.port == port  # same address after the "restart"
        assert await roundtrip() == b"ping"
    finally:
        await proxy.stop()
        backend.close()


# ---------------------------------------------------------------------------
# Crash recovery: kill the process mid-triage (task 16, Req 6.8)
# ---------------------------------------------------------------------------


@requires_stack
async def test_crash_recovery_kill_mid_triage_then_reaper_then_refire_is_accepted(scratch_dsn: str) -> None:
    assert TEST_REDIS_URL is not None
    env = _app_env(scratch_dsn, TEST_REDIS_URL)
    alert = {"service_name": "auth-db", "error_code": f"CRASH_{uuid4().hex[:8]}", "summary": "crash recovery"}

    doomed = AppProcess({**env, "CHAOS_HANG_TRIAGE": "1"})
    try:
        doomed.start()
        await doomed.wait_ready()
        async with httpx.AsyncClient(base_url=doomed.url, timeout=10.0) as client:
            posted = await client.post("/webhooks/alerts", json=alert)
            assert posted.status_code == 202
            incident_id = posted.json()["incident_id"]
            assert (await _incident(client, incident_id))["state"] == "TRIAGING"
        doomed.kill()  # the worker dies with the incident in flight and the lock held in Redis
    finally:
        doomed.stop()

    survivor = AppProcess(env)
    try:
        survivor.start()
        await survivor.wait_ready()
        async with httpx.AsyncClient(base_url=survivor.url, timeout=10.0) as client:
            final: dict[str, str] = {}

            async def left_triaging() -> bool:
                final.update(await _incident(client, incident_id))
                return final["state"] != "TRIAGING"

            # The row must be older than TRIAGE_TIMEOUT_SECONDS (10 s) before the reaper touches it.
            await _eventually(left_triaging, 90.0, "the reaper to recover the orphaned TRIAGING incident")
            # FAILED (recovered_after_crash) or resumed from the checkpoint (then it awaits approval).
            assert final["state"] in {"FAILED", "AWAITING_APPROVAL", "NO_ACTION"}, final
            if final["state"] == "AWAITING_APPROVAL":
                reply = await client.post("/api/demo/reply", json={"incident_id": incident_id, "choice": 1})
                assert reply.status_code == 202

                async def resolved() -> bool:
                    return (await _incident(client, incident_id))["state"] == "RESOLVED"

                await _eventually(resolved, 30.0, "the resumed incident to resolve")
            refired = await client.post("/webhooks/alerts", json=alert)
            assert refired.status_code == 202, refired.text
            assert refired.json()["incident_id"] != incident_id
    finally:
        survivor.stop()


# ---------------------------------------------------------------------------
# 60-alert storm against Postgres and Redis (task 22, Req 10.3)
# ---------------------------------------------------------------------------


@requires_stack
async def test_alert_storm_60_distinct_alerts_stays_bounded(scratch_dsn: str) -> None:
    assert TEST_REDIS_URL is not None
    app = AppProcess(_app_env(scratch_dsn, TEST_REDIS_URL, PAGE_RATE_PER_MINUTE="6"))
    prefix = f"ST{uuid4().hex[:6]}_"
    services = ("auth-db", "payment-gateway", "ledger-worker")
    try:
        app.start()
        await app.wait_ready()
        started = time.monotonic()
        async with httpx.AsyncClient(base_url=app.url, timeout=30.0) as client:
            codes = [f"{prefix}{i}" for i in range(60)]
            responses = await asyncio.gather(
                *(
                    client.post(
                        "/webhooks/alerts",
                        json={"service_name": services[i % 3], "error_code": code, "summary": "storm"},
                    )
                    for i, code in enumerate(codes)
                )
            )
            assert [r.status_code for r in responses] == [202] * 60

            async def settled() -> bool:
                rows = [r for r in (await client.get("/api/incidents")).json() if r["error_code"].startswith(prefix)]
                return len(rows) == 60 and not any(r["state"] in {"TRIAGING", "EXECUTING"} for r in rows)

            await _eventually(settled, 90.0, "all 60 incidents to leave the in-flight states")
            rows = [r for r in (await client.get("/api/incidents")).json() if r["error_code"].startswith(prefix)]
            assert {r["state"] for r in rows} <= {"AWAITING_APPROVAL", "NO_ACTION", "FAILED"}
            outbox = [m["text"] for m in (await client.get("/api/demo/outbox", params={"limit": 100})).json()]
            individual = [t for t in outbox if t.startswith("INC-") and " FAILED." not in t]
            summaries = [t for t in outbox if t.startswith("ALERTS:")]
            minutes = int((time.monotonic() - started) // 60)
            assert len(individual) <= 6 * (1 + minutes)
            assert len(summaries) <= 1 + minutes
    finally:
        app.stop()


# ---------------------------------------------------------------------------
# Postgres and Redis outage through a killable proxy (task 23, Req 7.4, 7.5)
# ---------------------------------------------------------------------------


@requires_stack
@pytest.mark.parametrize("victim", ["postgres", "redis"])
async def test_outage_returns_503_with_retry_after_then_recovers_without_restart(
    scratch_dsn: str, victim: str
) -> None:
    assert TEST_REDIS_URL is not None
    targets = {"postgres": _hostport(scratch_dsn, 5432), "redis": _hostport(TEST_REDIS_URL, 6379)}
    proxy = TcpProxy(*targets[victim])
    await proxy.start()
    database_url, redis_url = scratch_dsn, TEST_REDIS_URL
    if victim == "postgres":
        database_url = _with_hostport(scratch_dsn, "127.0.0.1", proxy.port)
    else:
        redis_url = _with_hostport(TEST_REDIS_URL, "127.0.0.1", proxy.port)
    app = AppProcess(_app_env(database_url, redis_url))
    prefix = f"OUT{uuid4().hex[:6]}_"
    seq = iter(range(10_000))

    def alert() -> dict[str, str]:
        return {"service_name": "auth-db", "error_code": f"{prefix}{next(seq)}", "summary": "outage"}

    try:
        app.start()
        await app.wait_ready()
        async with httpx.AsyncClient(base_url=app.url, timeout=20.0) as client:
            assert (await client.post("/webhooks/alerts", json=alert())).status_code == 202

            await proxy.stop()  # the dependency "stops": live connections reset, new ones refused
            seen: dict[str, Any] = {}

            async def answers_503() -> bool:
                resp = await client.post("/webhooks/alerts", json=alert())
                seen["status"], seen["retry_after"] = resp.status_code, resp.headers.get("Retry-After")
                return resp.status_code == 503

            await _eventually(answers_503, 30.0, "a 503 while the dependency is down")
            assert seen["retry_after"] == "5"
            ready = await client.get("/readyz")
            assert ready.status_code == 503 and ready.json()["checks"][victim]["ok"] is False
            assert (await client.get("/healthz")).status_code == 200

            await proxy.start()  # same port: the app is not restarted and not reconfigured

            async def answers_202() -> bool:
                return (await client.post("/webhooks/alerts", json=alert())).status_code == 202

            await _eventually(answers_202, 60.0, "202 after the dependency returned")
            assert app.proc is not None and app.proc.poll() is None  # same process throughout
            assert (await client.get("/readyz")).status_code == 200
    finally:
        app.stop()
        await proxy.stop()
