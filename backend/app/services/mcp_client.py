"""``TelemetryPort`` over the real MCP protocol (stdio subprocess).

``McpSubprocessTelemetry`` keeps ONE long-lived ``python -m backend.app.mcp.server``
subprocess and one MCP ``ClientSession`` per worker (Req 10.1), created lazily on the first
call. The ``get_incident_context`` tool result is parsed from JSON. The subprocess receives
only ``MCP_READER_DATABASE_URL`` (the restricted ``mcp_reader`` role), never the superuser
``DATABASE_URL``. Any failure or a 5 s per-call timeout yields a ``DEGRADED`` context (Req 2.3).

Concurrency: ``mcp`` multiplexes requests on one ``ClientSession`` by JSON-RPC request id (the
receive loop routes each response to its own waiter) and the FastMCP server handles each request
in its own task, so concurrent ``call_tool`` calls on one session are safe. An
``asyncio.Semaphore(TELEMETRY_MAX_CONCURRENCY)`` bounds the calls in flight, so there is never
more than one subprocess (at most ``TELEMETRY_MAX_CONCURRENCY`` is the contract) and never more
than N concurrent lookups. Time spent waiting for the semaphore is NOT charged to the 5 s
per-call timeout; the caller's overall triage timeout covers it.

Reconnect: the session is entered and exited by one dedicated owner task (anyio cancel scopes
must be exited by the task that entered them). The owner watches the subprocess output through
a forwarding stream; when it ends (subprocess died) the connection is marked dead, pending calls
fail with ``CONNECTION_CLOSED`` and the next call respawns. A call that fails on the transport
(anything but a parse error) is retried once on a fresh connection; a call that times out
discards the connection (a hung server is indistinguishable from a slow one) and degrades.

Requirements: 2.1, 2.2, 2.3, 10.1.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.message import SessionMessage

from backend.app.agents.ports import Runbook, TelemetryContext
from backend.app.mcp.server import IncidentContext
from backend.app.services.telemetry_adapters import to_telemetry_context

logger = logging.getLogger("pagemaster.mcp_client")

MCP_CALL_TIMEOUT_SECONDS: Final[float] = 5.0
DEFAULT_TELEMETRY_MAX_CONCURRENCY: Final[int] = 4
ACLOSE_TIMEOUT_SECONDS: Final[float] = 10.0
_TOOL_NAME: Final[str] = "get_incident_context"
_DEFAULT_SERVER_ARGS: Final[tuple[str, ...]] = ("-m", "backend.app.mcp.server")
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_PASSTHROUGH_ENV: Final[tuple[str, ...]] = (
    "PATH",
    "SYSTEMROOT",
    "HOME",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "PYTHONPATH",
    "LANG",
)


def _degraded(service_name: str, reason: str) -> TelemetryContext:
    logger.debug("degraded context for %s: %s", service_name, reason)
    # Empty root_cause lets triage keep the alert's own summary.
    return TelemetryContext(confidence="DEGRADED", root_cause="", runbooks=())


def parse_tool_result(result: Any) -> IncidentContext:
    """Parse a ``CallToolResult`` into an ``IncidentContext`` (raises ``ValueError``)."""
    if getattr(result, "isError", False):
        raise ValueError("tool returned an error")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return IncidentContext.model_validate(structured)
    for block in getattr(result, "content", None) or ():
        text = getattr(block, "text", None)
        if isinstance(text, str):
            return IncidentContext.model_validate(json.loads(text))
    raise ValueError("tool result has no JSON content")


class _Connection:
    """One MCP subprocess + session, owned (entered and exited) by a single task."""

    def __init__(self, params: StdioServerParameters) -> None:
        loop = asyncio.get_running_loop()
        self.ready: asyncio.Future[ClientSession] = loop.create_future()
        self.ready.add_done_callback(_consume_future_error)
        self.died = asyncio.Event()  # set once the subprocess or session is gone
        self._wake = asyncio.Event()
        self.task: asyncio.Task[None] = loop.create_task(self._run(params), name="mcp-session")

    @property
    def dead(self) -> bool:
        return self.died.is_set()

    async def _run(self, params: StdioServerParameters) -> None:
        try:
            async with stdio_client(params) as (read, write):
                forward_send, forward_recv = anyio.create_memory_object_stream[
                    SessionMessage | Exception
                ](0)

                async def forward() -> None:
                    # Mirror the subprocess output. Its end means the subprocess died.
                    try:
                        async with forward_send:
                            async for item in read:
                                await forward_send.send(item)
                    finally:
                        self.died.set()
                        self._wake.set()

                async with anyio.create_task_group() as tg:
                    tg.start_soon(forward)
                    try:
                        async with ClientSession(forward_recv, write) as session:
                            await session.initialize()
                            if not self.ready.done():
                                self.ready.set_result(session)
                            await self._wake.wait()
                    finally:
                        tg.cancel_scope.cancel()
        except asyncio.CancelledError:
            if not self.ready.done():
                self.ready.cancel()
            raise
        except BaseException as exc:  # spawn/initialize/teardown errors
            if not self.ready.done():
                self.ready.set_exception(exc)
            else:
                logger.debug("mcp session ended with %s", type(exc).__name__)
        finally:
            self.died.set()
            if not self.ready.done():
                self.ready.set_exception(ConnectionError("mcp session closed before ready"))

    def request_close(self) -> None:
        """Ask the owner to tear the subprocess down. Never blocks, safe under cancellation."""
        self.died.set()
        if self.ready.done():
            self._wake.set()
        else:
            self.task.cancel()


def _consume_future_error(fut: asyncio.Future[Any]) -> None:
    if not fut.cancelled():
        fut.exception()  # mark retrieved; callers that await it still see the error


class McpSubprocessTelemetry:
    """``TelemetryPort`` + ``RunbookPort.list_approved`` over one long-lived stdio MCP session."""

    def __init__(
        self,
        reader_dsn: str,
        *,
        timeout: float = MCP_CALL_TIMEOUT_SECONDS,
        cwd: Path | None = None,
        max_concurrency: int = DEFAULT_TELEMETRY_MAX_CONCURRENCY,
        server_args: Sequence[str] = _DEFAULT_SERVER_ARGS,
        extra_env: Mapping[str, str] | None = None,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self._dsn = reader_dsn
        self._timeout = timeout
        self._cwd = cwd if cwd is not None else _REPO_ROOT
        self._server_args = tuple(server_args)
        self._extra_env = dict(extra_env or {})
        self.max_concurrency = max_concurrency
        self._sem = asyncio.Semaphore(max_concurrency)
        self._conn: _Connection | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    def _params(self) -> StdioServerParameters:
        env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
        env.update(self._extra_env)
        env["MCP_READER_DATABASE_URL"] = self._dsn
        return StdioServerParameters(
            command=sys.executable,
            args=list(self._server_args),
            env=env,
            cwd=self._cwd,
        )

    def _current(self) -> _Connection:
        """The live connection, spawning a new one when none exists or it died (no awaits)."""
        if self._closed:
            raise RuntimeError("telemetry client is closed")
        conn = self._conn
        if conn is None or conn.dead or conn.task.done():
            if conn is not None:
                conn.request_close()
            conn = self._conn = _Connection(self._params())
            self._tasks.add(conn.task)
            conn.task.add_done_callback(self._tasks.discard)
        return conn

    def _discard(self, conn: _Connection) -> None:
        if self._conn is conn:
            self._conn = None
        conn.request_close()

    @staticmethod
    async def _call_or_death(conn: _Connection, session: ClientSession, service_name: str) -> Any:
        """``call_tool``, abandoned as soon as the subprocess is known to be gone.

        A request registered just after the session's receive loop ended would otherwise wait
        for the full call timeout.
        """
        call = asyncio.ensure_future(session.call_tool(_TOOL_NAME, {"service_name": service_name}))
        death = asyncio.ensure_future(conn.died.wait())
        try:
            await asyncio.wait({call, death}, return_when=asyncio.FIRST_COMPLETED)
            if call.done():
                return call.result()
            raise ConnectionError("mcp subprocess died during call")
        finally:
            for fut in (call, death):
                if not fut.done():
                    fut.cancel()

    async def _attempt(self, service_name: str) -> IncidentContext:
        conn = self._current()
        try:
            session = await asyncio.shield(conn.ready)
            result = await self._call_or_death(conn, session, service_name)
            return parse_tool_result(result)
        except ValueError:
            raise  # bad payload from a healthy session: keep the connection
        except BaseException:
            self._discard(conn)  # transport error, timeout or cancellation: respawn next time
            raise

    async def _call(self, service_name: str) -> IncidentContext:
        """One lookup; a transport failure is retried once on a freshly spawned session."""
        try:
            return await self._attempt(service_name)
        except (ValueError, TimeoutError, asyncio.CancelledError):
            raise
        except Exception as exc:
            logger.warning("mcp transport error (%s); reconnecting once", type(exc).__name__)
            return await self._attempt(service_name)

    async def get_incident_context(self, service_name: str) -> TelemetryContext:
        async with self._sem:  # waiting here is charged to the caller's overall triage timeout
            try:
                async with asyncio.timeout(self._timeout):
                    ctx = await self._call(service_name)
            except Exception as exc:  # incl. TimeoutError, spawn/protocol/parse errors (Req 2.3)
                logger.warning("mcp telemetry failed for %s: %s", service_name, type(exc).__name__)
                return _degraded(service_name, "unavailable")
        return to_telemetry_context(ctx)

    async def list_approved(self, service_name: str) -> Sequence[Runbook]:
        return (await self.get_incident_context(service_name)).runbooks

    async def aclose(self) -> None:
        """Stop the subprocess and wait for the owner task. Idempotent."""
        self._closed = True
        conn, self._conn = self._conn, None
        if conn is not None:
            conn.request_close()
        pending = [t for t in self._tasks if not t.done()]
        if not pending:
            return
        _, still = await asyncio.wait(pending, timeout=ACLOSE_TIMEOUT_SECONDS)
        for task in still:
            task.cancel()
        for task in still:
            with contextlib.suppress(BaseException):
                await task
