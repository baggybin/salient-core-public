from __future__ import annotations

import asyncio
import hmac
import json
import logging
import math
import secrets
import select
import socket
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import CancelledError, Future
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final

from .runtime import AgentTool, JsonValue, ToolBundle

_log = logging.getLogger("salient.daemon.codex_mcp")


class GatewayAttachError(RuntimeError):
    """The codex MCP bus gateway did not confirm the agent's tool schemas were
    delivered (no `tools/list` within the attach timeout). Raised by
    `wait_attached`; the backend fails closed and the runner retries/faults
    rather than run a silently bus-less agent."""

    def __init__(self, owner: str, rung: str) -> None:
        super().__init__(f"codex gateway attach failed for {owner!r}: {rung}")
        self.owner = owner
        self.rung = rung


_PROTOCOL_VERSION: Final = "2025-03-26"
# Ceiling on a single tool handler. Enforced on BOTH sides: the HTTP thread's
# poll deadline bounds the client-visible response, and an asyncio.wait_for on
# the owner loop bounds the coroutine itself — so a handler that ignores
# cancellation (or whose HTTP thread has already given up) still can't run
# unbounded. Mirrored into codex_config's tool_timeout_sec so the Codex client
# and the gateway agree on the budget.
_TOOL_TIMEOUT_SEC: Final = 120
# Blocking delegation tools (`ask_agent` / `ask_agents` / `ask_operator` / …) exist
# to WAIT — for a child's reply, a swarm fan-out, or an operator answer — and
# manage their own caller-side wait internally (bus `_compute_ask_agent_timeout`,
# capped ~4h). Bounding them at the default 120s made codex agents give up on any
# swarm or deep delegation after two minutes (the children keep running; the caller
# just stops listening). Give these a ceiling ABOVE the bus cap so the bus's own
# timeout — with its proper "did not reply within wait window" error — always fires
# first. Non-blocking tools keep the tight 120s bound.
_BLOCKING_TOOL_TIMEOUT_SEC: Final = 4 * 3600 + 300  # 4h + slop
# Ceiling for a NON-blocking handler that is nonetheless legitimately long. Many
# security tools take a caller-supplied `timeout_s` and internally default to a
# `long_timeout_seconds` config (up to 7200s for keyspace) — the blunt 120s bound
# killed them mid-run under Codex. We honor a longer budget for these but CLAMP it
# to a hard max, because the caller's `timeout_s` is MODEL-CONTROLLED input: an
# absurd value must not pin a handler open near the 4h blocking cap. The clamp
# sits above the largest configured tool default (keyspace 7200s) + slop so a
# well-behaved tool's OWN timeout fires first, and below _BLOCKING_TOOL_TIMEOUT_SEC.
# NOTE: this bounds the CLIENT-VISIBLE wait, not a handler that swallows
# cancellation (that leaks a coroutine past the deadline — a pre-existing property,
# same shape as the ListenerRegistry background-and-reap pattern; the real fix is a
# reaper + a concurrency cap on long-ceiling handlers, both out of scope here).
_HARD_MAX_TOOL_TIMEOUT_SEC: Final = 7800  # 2h10m — covers keyspace 7200 + margin
_TOOL_TIMEOUT_SLOP_SEC: Final = 60


def _positive_timeout(raw: object) -> float | None:
    """Coerce a caller-supplied `timeout_s` to a positive, FINITE number of
    seconds, or None. It is MODEL-controlled, untrusted input, so reject bool
    (an int subclass), non-finite floats (inf / nan, reachable as `Infinity`
    over JSON or via a huge string like '1e400'), and non-numerics. A huge int
    is capped to the hard max BEFORE float() so `float(10**400)` can't overflow;
    a non-finite float is rejected so the caller's `int(declared)` can't raise
    OverflowError on the dispatch hot path. Numeric strings are accepted (models
    sometimes stringify numbers)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        if raw <= 0:
            return None
        return float(min(raw, _HARD_MAX_TOOL_TIMEOUT_SEC))
    if isinstance(raw, float):
        return raw if (raw > 0 and math.isfinite(raw)) else None
    if isinstance(raw, str):
        try:
            val = float(raw.strip())  # '1e400' -> inf (not an error), 'nan' -> nan
        except ValueError:
            return None
        return val if (val > 0 and math.isfinite(val)) else None
    return None


def _schema_declares_timeout(schema: object) -> bool:
    """True when the tool's INPUT SCHEMA declares a top-level `timeout_s`
    property — an AUTHOR-controlled (trusted, static, model-unreachable) signal
    that the handler is long-capable, so it earns the long ceiling even when the
    caller omits the arg. Distinct from reading `timeout_s` out of the
    model-controlled args."""
    if not isinstance(schema, Mapping):
        return False
    props = schema.get("properties")
    return isinstance(props, Mapping) and "timeout_s" in props


def _tool_timeout(
    bare_name: str,
    args: Mapping[str, object] | None = None,
    schema: object | None = None,
) -> int:
    """Per-call gateway ceiling.

    - `ask_*` delegation tools manage their own long wait internally → 4h.
    - Otherwise, honor an explicit caller `timeout_s` (floored at the base 120s
      so a tiny model value can't cut legit work, clamped at the hard max).
    - Else, if the tool's schema DECLARES `timeout_s` (author says long-capable),
      give it the hard-max backstop — its OWN internal timeout fires first.
    - Else the tight 120s bound.

    `args`/`schema` default to None so the pure-name call form stays valid."""
    if bare_name.startswith("ask_"):
        return _BLOCKING_TOOL_TIMEOUT_SEC
    declared = _positive_timeout((args or {}).get("timeout_s"))
    if declared is not None:
        return min(
            max(int(declared) + _TOOL_TIMEOUT_SLOP_SEC, _TOOL_TIMEOUT_SEC),
            _HARD_MAX_TOOL_TIMEOUT_SEC,
        )
    if _schema_declares_timeout(schema):
        return _HARD_MAX_TOOL_TIMEOUT_SEC
    return _TOOL_TIMEOUT_SEC


_SHARED_GATEWAY: CodexMcpGateway | None = None


def _json_data(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return {str(key): _json_data(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str):
        return [_json_data(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class McpCredential:
    owner: str
    token: str
    url: str
    bearer_token_env_var: str

    def codex_config(self) -> dict[str, JsonValue]:
        return {
            "url": self.url,
            "bearer_token_env_var": self.bearer_token_env_var,
            "required": True,
            "startup_timeout_sec": 10,
            # The codex CLI's own per-tool wait. Must cover the longest tool the
            # gateway will run (a blocking ask_* delegation) — the gateway still
            # bounds every INDIVIDUAL tool per `_tool_timeout`, so a non-blocking
            # tool that wedges is answered (with an error) at 120s regardless.
            "tool_timeout_sec": _BLOCKING_TOOL_TIMEOUT_SEC,
        }


@dataclass(slots=True)
class _Catalog:
    owner: str
    tools: ToolBundle
    loop: asyncio.AbstractEventLoop
    pending: set[Future[JsonValue]]
    revoked: bool = False
    # Set by the `tools/list` handler on the first authenticated schema fetch for
    # this token — i.e. "codex actually received the bus tool schemas". A
    # threading.Event so the HTTP-server thread can set it and the async
    # backend.connect() can await it (via wait_attached). T2.4b-adjacent codex-bus fix.
    attach_event: threading.Event = field(default_factory=threading.Event)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, sock: socket.socket, gateway: CodexMcpGateway) -> None:
        self.gateway = gateway
        super().__init__(sock.getsockname(), _Handler, bind_and_activate=False)
        self.socket.close()
        self.socket = sock
        self.server_address = sock.getsockname()
        self.server_activate()


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._write(404, {"error": "not found"})
            return
        authorization = self.headers.get("Authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        catalog = self.server.gateway._catalog(token)
        if catalog is None:
            self._write(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._write(400, {"error": "invalid JSON"})
            return
        if not isinstance(payload, dict):
            self._write(400, {"error": "invalid JSON-RPC request"})
            return
        status, result = self.server.gateway._dispatch(catalog, payload, self._disconnected)
        self._write(status, result)

    def _disconnected(self) -> bool:
        readable, _, _ = select.select((self.connection,), (), (), 0)
        if not readable:
            return False
        try:
            disconnected = self.connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b""
            return bool(disconnected)
        except (BlockingIOError, ConnectionResetError, OSError):
            return True

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _write(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            return


class CodexMcpGateway:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._catalogs: dict[str, _Catalog] = {}
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._url: str | None = None

    @property
    def url(self) -> str:
        if self._url is None:
            raise RuntimeError("MCP gateway is not running")
        return self._url

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self) -> None:
        if self._server is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", 0))
        sock.listen(socket.SOMAXCONN)
        server = _Server(sock, self)
        port = int(server.server_address[1])
        self._server = server
        self._url = f"http://127.0.0.1:{port}/mcp"
        thread = threading.Thread(
            target=server.serve_forever,
            name="salient-codex-mcp",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def issue(
        self,
        owner: str,
        tools: ToolBundle,
        *,
        bearer_token_env_var: str = "SALIENT_CODEX_MCP_TOKEN",
    ) -> McpCredential:
        token = secrets.token_urlsafe(32)
        loop = asyncio.get_running_loop()
        # Start-check AND url read happen UNDER the lock so the returned
        # credential can never capture a URL that a concurrent teardown is about
        # to invalidate. Since revoke() no longer stops the server, the URL is a
        # process-lifetime constant once bound (lazy start preserved).
        with self._lock:
            if self._server is None:
                self.start()
            url = self.url
            # Supersede any stale catalog for the same owner (a prior backend
            # instance that didn't cleanly revoke). Deterministic, under the
            # lock, so at most one catalog per owner ever — self-healing against
            # leaks, and NOT the agent-name-keyed revoke hazard (there is no
            # server-lifecycle side effect here).
            for stale, cat in tuple(self._catalogs.items()):
                if cat.owner == owner:
                    self._catalogs.pop(stale, None)
                    _log.warning("codex gateway: superseding stale catalog for %s", owner)
            self._catalogs[token] = _Catalog(owner, tools, loop, set())
        return McpCredential(owner, token, url, bearer_token_env_var)

    def revoke(self, token: str) -> None:
        """Drop a credential. IDEMPOTENT (contractual): a double-revoke — which
        the backend's fail-closed connect path deliberately does vs the later
        disconnect() — is a no-op on the second call.

        The server is intentionally NOT stopped when the last credential is
        revoked. The old stop-on-last-revoke was a check-then-act race:
        `_stop_async` tore the server down on a background thread while the very
        next `issue()` still saw `self._server` set, skipped `start()`, and
        minted a credential capturing a URL whose server was already dying — the
        codex subprocess then connected to a dead endpoint and silently got zero
        bus tools. The server now lives for the daemon's life; it is torn down
        only by `close()` at shutdown. See the codex-bus-gateway-race fix."""
        catalog: _Catalog | None = None
        with self._lock:
            for stored in tuple(self._catalogs):
                if hmac.compare_digest(stored, token):
                    catalog = self._catalogs.pop(stored)
                    # Flip under the same lock _dispatch must take to schedule a
                    # tool call, so a concurrent dispatch either sees revoked and
                    # bails, or is already in `pending` and gets cancelled below.
                    catalog.revoked = True
                    break
        if catalog is not None:
            for pending in tuple(catalog.pending):
                pending.cancel()

    async def wait_attached(self, token: str, timeout: float = 25.0) -> None:
        """Block until codex has fetched this token's bus-tool schemas (the
        first authenticated `tools/list`), i.e. the tools are actually in the
        model's session. Returns fast on success; on timeout raises
        GatewayAttachError with the failure rung so the backend can fail closed
        instead of running a silently bus-less agent."""
        catalog = self._catalog(token)
        if catalog is None:
            raise GatewayAttachError("?", "credential not found (revoked before attach)")
        attached = await asyncio.to_thread(catalog.attach_event.wait, timeout)
        if not attached:
            # Diagnose the rung reached, for the operator.
            rung = (
                f"no tools/list within {timeout:.0f}s "
                "(codex never connected, bad token, or empty schema)"
            )
            raise GatewayAttachError(catalog.owner, rung)

    def close(self) -> None:
        server = self._server
        self._server = None
        self._url = None
        with self._lock:
            catalogs = tuple(self._catalogs.values())
            self._catalogs.clear()
        for catalog in catalogs:
            for pending in tuple(catalog.pending):
                pending.cancel()
        if server is not None:
            server.shutdown()
            server.server_close()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=2)

    def _catalog(self, token: str) -> _Catalog | None:
        with self._lock:
            for stored, catalog in self._catalogs.items():
                if hmac.compare_digest(stored, token):
                    return catalog
        return None

    def _dispatch(
        self,
        catalog: _Catalog,
        request: dict[str, Any],
        disconnected: Callable[[], bool] = lambda: False,
    ) -> tuple[int, dict[str, Any]]:
        request_id = request.get("id")
        method = request.get("method")
        if method == "initialize":
            result: dict[str, Any] = {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "salient", "version": "1"},
            }
            return 200, {"jsonrpc": "2.0", "id": request_id, "result": result}
        if method == "notifications/initialized":
            return 202, {}
        if method == "ping":
            return 200, {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            tools = [self._tool_schema(tool) for tool in catalog.tools.tools]
            if not catalog.attach_event.is_set():
                # First schema fetch for this token = the bus tools are now in
                # codex's session. Signals wait_attached() that attach succeeded.
                catalog.attach_event.set()
                _log.info(
                    "codex gateway: %s attached (%d bus tools delivered)",
                    catalog.owner,
                    len(tools),
                )
            return 200, {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": tools},
            }
        if method != "tools/call":
            return 404, self._error(request_id, -32601, "method not found")
        params = request.get("params")
        if not isinstance(params, dict):
            return 400, self._error(request_id, -32602, "invalid params")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return 400, self._error(request_id, -32602, "invalid params")
        tool = next(
            (candidate for candidate in catalog.tools.tools if candidate.name == name), None
        )
        if tool is None:
            # Codex presents/forwards MCP tools under a server-qualified name
            # (e.g. "salient__list_agents"), and salient's per-agent prompts are
            # written in the Claude wire form "mcp__bus__<alias>__<tool>", which
            # the model may echo verbatim. Bus bare names are single snake_case
            # tokens (no "__"), so the last "__"-delimited segment resolves any
            # of those forms unambiguously — the same dual-namespace tolerance
            # the Claude SDK path already has (bus tools registered on both the
            # `mcp__<alias>__` and `mcp__bus__<alias>__` servers).
            bare = name.rsplit("__", 1)[-1]
            if bare != name:
                tool = next(
                    (candidate for candidate in catalog.tools.tools if candidate.name == bare),
                    None,
                )
        if tool is None:
            return 404, self._error(request_id, -32602, f"unknown tool: {name!r}")

        # Blocking delegation tools (ask_*) manage their own long wait; a tool that
        # declares `timeout_s` (or whose caller passes one) earns a longer, clamped
        # ceiling; everything else stays on the tight 120s bound. Both deadlines
        # below derive from this single value, so they can't skew.
        tool_timeout = _tool_timeout(tool.name, arguments, tool.input_schema)

        async def invoke() -> JsonValue:
            # Loop-side deadline: bounds the coroutine even if the HTTP thread
            # has already returned/died or the handler ignores cancel().
            return await asyncio.wait_for(tool.handler(arguments), tool_timeout)

        # Schedule the handler and register the future in ONE critical section,
        # gated on the revoked flag. run_coroutine_threadsafe only does a
        # non-blocking call_soon_threadsafe, so holding _lock across it is safe
        # and closes the revoke-vs-dispatch race: revoke() sets `revoked` and
        # snapshots `pending` under this same lock, so every future is either
        # seen-and-cancelled or never scheduled.
        with self._lock:
            if catalog.revoked:
                return 200, {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": "agent revoked"}],
                        "isError": True,
                    },
                }
            future: Future[JsonValue] = asyncio.run_coroutine_threadsafe(invoke(), catalog.loop)
            catalog.pending.add(future)
        try:
            # Thread-side deadline: bounds the client-visible response. Break on
            # future.done() so a handler that itself raises TimeoutError isn't
            # confused with a poll timeout (in 3.11+ asyncio.TimeoutError,
            # concurrent.futures.TimeoutError and builtins.TimeoutError are the
            # same type). Give the loop-side wait_for a small grace so its clean
            # cancellation lands first.
            deadline = time.monotonic() + tool_timeout + 1
            while not future.done():
                if disconnected() or time.monotonic() >= deadline:
                    future.cancel()
                    break
                try:
                    future.result(timeout=0.1)
                except FutureTimeoutError:
                    pass
            tool_result = future.result()  # value, or re-raises the handler error
            text = json.dumps(tool_result, separators=(",", ":"))
            return 200, {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            }
        except (CancelledError, FutureTimeoutError, RuntimeError, ValueError, OSError) as error:
            future.cancel()
            return 200, {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": str(error)}],
                    "isError": True,
                },
            }
        finally:
            with self._lock:
                catalog.pending.discard(future)

    @staticmethod
    def _tool_schema(tool: AgentTool) -> dict[str, Any]:
        schema = _json_data(tool.input_schema)
        result: dict[str, Any] = {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": schema,
        }
        if tool.annotations:
            result["annotations"] = _json_data(tool.annotations)
        return result

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }


def translate_external_mcp(config: dict[str, JsonValue]) -> dict[str, JsonValue]:
    transport = config.get("type", "stdio")
    if transport == "stdio":
        command = config.get("command")
        if not isinstance(command, str) or not command:
            raise ValueError("stdio MCP server requires command")
        result = {key: value for key, value in config.items() if key != "type"}
        return result
    if transport == "http":
        url = config.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError("HTTP MCP server requires url")
        return {key: value for key, value in config.items() if key != "type"}
    raise ValueError(f"unsupported Codex MCP transport: {transport}")


def get_codex_mcp_gateway() -> CodexMcpGateway:
    global _SHARED_GATEWAY
    if _SHARED_GATEWAY is None:
        _SHARED_GATEWAY = CodexMcpGateway()
    return _SHARED_GATEWAY


def close_codex_mcp_gateway() -> None:
    """Tear down the shared gateway server at daemon shutdown. No-op if it was
    never started (lazy). Since revoke() no longer stops-on-last, this is the
    ONLY place the server is stopped for the daemon's life."""
    global _SHARED_GATEWAY
    if _SHARED_GATEWAY is not None:
        _SHARED_GATEWAY.close()
        _SHARED_GATEWAY = None
