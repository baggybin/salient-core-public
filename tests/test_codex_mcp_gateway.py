from __future__ import annotations

import asyncio
import json
import threading
import urllib.error
import urllib.request

from salient_core.runtime import AgentTool, ToolBundle


async def _echo(arguments):
    return {"echo": arguments.get("text", "")}


def _post(url: str, token: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_gateway_auth_isolation_and_revoke() -> None:
    from salient_core.codex_mcp import CodexMcpGateway

    bundle = ToolBundle((AgentTool("echo", "echo text", {"type": "object"}, _echo),))

    async def scenario() -> None:
        gateway = CodexMcpGateway()
        gateway.start()
        first = gateway.issue("agent-a", bundle)
        second = gateway.issue("agent-b", ToolBundle())
        try:
            status, listed = await asyncio.to_thread(
                _post,
                gateway.url,
                first.token,
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            )
            assert status == 200
            assert [tool["name"] for tool in listed["result"]["tools"]] == ["echo"]

            status, called = await asyncio.to_thread(
                _post,
                gateway.url,
                first.token,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "ok"}},
                },
            )
            assert status == 200
            assert json.loads(called["result"]["content"][0]["text"]) == {"echo": "ok"}

            status, _ = await asyncio.to_thread(
                _post,
                gateway.url,
                second.token,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {}},
                },
            )
            assert status == 404

            gateway.revoke(first.token)
            status, _ = await asyncio.to_thread(
                _post,
                gateway.url,
                first.token,
                {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
            )
            assert status == 401
        finally:
            gateway.close()

    asyncio.run(scenario())


def test_blocking_delegation_tools_get_a_long_gateway_timeout() -> None:
    # ask_* tools block waiting for a child/swarm/operator and manage their own
    # long caller-side wait; the gateway must not cancel them at the default 120s
    # (that made codex agents give up on swarms after 2 min). Non-blocking tools
    # keep the tight bound.
    from salient_core.codex_mcp import (
        _BLOCKING_TOOL_TIMEOUT_SEC,
        _TOOL_TIMEOUT_SEC,
        McpCredential,
        _tool_timeout,
    )

    assert _BLOCKING_TOOL_TIMEOUT_SEC > _TOOL_TIMEOUT_SEC
    for blocking in ("ask_agent", "ask_agents", "ask_operator", "ask_consensus"):
        assert _tool_timeout(blocking) == _BLOCKING_TOOL_TIMEOUT_SEC
    for quick in ("context_read", "list_agents", "scanner_scan", "context_write"):
        assert _tool_timeout(quick) == _TOOL_TIMEOUT_SEC

    # The codex CLI's own per-tool wait must cover the longest gateway tool.
    cfg = McpCredential("owner", "tok", "http://x/mcp", "ENV").codex_config()
    assert cfg["tool_timeout_sec"] == _BLOCKING_TOOL_TIMEOUT_SEC


def test_long_foreground_tools_get_an_arg_and_schema_aware_timeout() -> None:
    # The blunt 120s bound killed legitimately-long foreground tools (a full scan,
    # a crack run) at 2 min under codex. Now: a tool that DECLARES timeout_s in its
    # schema (author signal it's long-capable) gets the long ceiling even when the
    # model omits the arg; an explicit model-supplied timeout_s is honored but
    # FLOORED at the base bound and CLAMPED at the hard max (it's model-controlled,
    # untrusted input); a plain tool with neither stays at the tight 120s.
    from salient_core.codex_mcp import (
        _HARD_MAX_TOOL_TIMEOUT_SEC,
        _TOOL_TIMEOUT_SEC,
        _TOOL_TIMEOUT_SLOP_SEC,
        _tool_timeout,
    )

    long_schema = {"type": "object", "properties": {"timeout_s": {"type": "number"}}}
    plain_schema = {"type": "object", "properties": {"target": {"type": "string"}}}

    # Schema declares timeout_s, caller omits it → hard-max backstop (its own
    # internal timeout fires first for well-behaved tools).
    assert _tool_timeout("sniff_capture", {}, long_schema) == _HARD_MAX_TOOL_TIMEOUT_SEC
    # No schema, no arg → tight bound (unchanged behavior).
    assert _tool_timeout("scanner_scan", {}, plain_schema) == _TOOL_TIMEOUT_SEC
    assert _tool_timeout("scanner_scan") == _TOOL_TIMEOUT_SEC
    # Explicit caller timeout_s → declared + slop, honored.
    assert (
        _tool_timeout("sniff_capture", {"timeout_s": 900}, long_schema)
        == 900 + _TOOL_TIMEOUT_SLOP_SEC
    )
    # Absurd model value is clamped to the hard max (no pinning open near the 4h cap).
    assert (
        _tool_timeout("sniff_capture", {"timeout_s": 10**9}, long_schema)
        == _HARD_MAX_TOOL_TIMEOUT_SEC
    )
    # A tiny model value is floored at the base bound (can't cut legit work shorter).
    assert _tool_timeout("sniff_capture", {"timeout_s": 5}, long_schema) == _TOOL_TIMEOUT_SEC
    # Stringified number (models do this) is coerced; junk/bool are ignored.
    assert (
        _tool_timeout("sniff_capture", {"timeout_s": "900"}, long_schema)
        == 900 + _TOOL_TIMEOUT_SLOP_SEC
    )
    assert _tool_timeout("x", {"timeout_s": "nope"}, plain_schema) == _TOOL_TIMEOUT_SEC
    assert _tool_timeout("x", {"timeout_s": True}, plain_schema) == _TOOL_TIMEOUT_SEC
    # keyspace's real 7200s crack budget fits under the hard max (the whole point).
    assert (
        _tool_timeout("keyspace_run", {"timeout_s": 7200}, long_schema)
        <= _HARD_MAX_TOOL_TIMEOUT_SEC
    )
    assert _tool_timeout("keyspace_run", {"timeout_s": 7200}, long_schema) >= 7200

    # Non-finite MODEL-controlled input MUST NOT crash: without a finiteness
    # guard, inf (reachable as JSON `Infinity`, or `float("1e400")`/`"1e400"`)
    # reaches `int(inf)` → unhandled OverflowError on the dispatch hot path. It is
    # rejected → falls back to the schema/default ceiling, never an exception.
    for bad in (float("inf"), float("nan"), "inf", "1e400", "nan"):
        assert (
            _tool_timeout("sniff_capture", {"timeout_s": bad}, long_schema)
            == _HARD_MAX_TOOL_TIMEOUT_SEC
        )
        assert _tool_timeout("scanner_scan", {"timeout_s": bad}, plain_schema) == _TOOL_TIMEOUT_SEC
    # A huge FINITE int must not overflow float() either — it's capped to the hard max.
    assert _tool_timeout("x", {"timeout_s": 10**400}, long_schema) == _HARD_MAX_TOOL_TIMEOUT_SEC


def test_gateway_resolves_server_qualified_tool_name() -> None:
    # Codex forwards MCP tools under a server-qualified name, and salient's
    # per-agent prompts use the Claude wire form "mcp__bus__<alias>__<tool>"
    # which the model may echo verbatim. The gateway must resolve any such form
    # to the bare tool name (its last "__"-delimited segment) — otherwise every
    # codex bus tool call fails "unknown tool" while text turns work.
    from salient_core.codex_mcp import CodexMcpGateway

    bundle = ToolBundle((AgentTool("list_agents", "list", {"type": "object"}, _echo),))

    async def scenario() -> None:
        gateway = CodexMcpGateway()
        gateway.start()
        cred = gateway.issue("manager", bundle)
        try:
            for call_name in (
                "list_agents",  # bare — always worked
                "mcp__bus__manager__list_agents",  # Claude wire form from the prompt
                "salient__list_agents",  # codex server-qualified form
            ):
                status, called = await asyncio.to_thread(
                    _post,
                    gateway.url,
                    cred.token,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": call_name, "arguments": {"text": "ok"}},
                    },
                )
                assert status == 200, call_name
                assert called["result"]["isError"] is False, call_name
                assert json.loads(called["result"]["content"][0]["text"]) == {"echo": "ok"}

            # A genuinely unknown tool still 404s — and the error names it.
            status, miss = await asyncio.to_thread(
                _post,
                gateway.url,
                cred.token,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "nope__does_not_exist", "arguments": {}},
                },
            )
            assert status == 404
            assert "does_not_exist" in miss["error"]["message"]
        finally:
            gateway.close()

    asyncio.run(scenario())


def test_external_mcp_translation_rejects_legacy_sse() -> None:
    from salient_core.codex_mcp import translate_external_mcp

    assert translate_external_mcp({"type": "stdio", "command": "server", "args": ["--safe"]}) == {
        "command": "server",
        "args": ["--safe"],
    }
    assert translate_external_mcp({"type": "http", "url": "https://mcp.invalid"}) == {
        "url": "https://mcp.invalid"
    }
    try:
        translate_external_mcp({"type": "sse", "url": "https://mcp.invalid"})
    except ValueError as error:
        assert "unsupported Codex MCP transport" in str(error)
    else:
        raise AssertionError("legacy SSE transport was accepted")


def test_gateway_runs_handler_on_owner_loop_and_cancels_on_revoke() -> None:
    from salient_core.codex_mcp import CodexMcpGateway

    async def scenario() -> None:
        owner_thread = threading.get_ident()
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def slow(_arguments):
            assert threading.get_ident() == owner_thread
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        gateway = CodexMcpGateway()
        gateway.start()
        credential = gateway.issue("owner", ToolBundle((AgentTool("slow", "", {}, slow),)))
        request = asyncio.create_task(
            asyncio.to_thread(
                _post,
                gateway.url,
                credential.token,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "slow", "arguments": {}},
                },
            )
        )
        await asyncio.wait_for(started.wait(), 1)
        gateway.revoke(credential.token)
        await asyncio.wait_for(cancelled.wait(), 1)
        await asyncio.wait_for(request, 1)
        # revoke cancels the in-flight handler but (post codex-bus-race fix) the
        # server stays up for the daemon's life — only close() stops it.
        assert gateway.running
        gateway.close()
        assert not gateway.running

    asyncio.run(scenario())


def test_gateway_dispatch_after_revoke_does_not_run_handler() -> None:
    # The revoke-vs-dispatch TOCTOU: a tools/call that reaches _dispatch after
    # revoke() has flipped the catalog's `revoked` flag must return isError and
    # never schedule the handler onto the owner loop.
    from salient_core.codex_mcp import CodexMcpGateway

    ran = threading.Event()

    async def handler(_arguments):
        ran.set()
        return {"ok": True}

    async def scenario() -> None:
        gateway = CodexMcpGateway()
        gateway.start()
        credential = gateway.issue(
            "owner", ToolBundle((AgentTool("t", "", {"type": "object"}, handler),))
        )
        catalog = gateway._catalog(credential.token)
        assert catalog is not None
        gateway.revoke(credential.token)  # flips catalog.revoked under _lock
        try:
            status, result = gateway._dispatch(
                catalog,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "t", "arguments": {}},
                },
            )
            assert status == 200
            assert result["result"]["isError"] is True
            await asyncio.sleep(0.05)
            assert not ran.is_set()
        finally:
            gateway.close()

    asyncio.run(scenario())


def test_gateway_bounds_runaway_handler_with_deadline(monkeypatch) -> None:
    # A handler that never completes must be cancelled and returned as isError
    # once the loop-side wait_for deadline fires, even though nothing revoked it.
    from salient_core import codex_mcp
    from salient_core.codex_mcp import CodexMcpGateway

    monkeypatch.setattr(codex_mcp, "_TOOL_TIMEOUT_SEC", 0.3)

    async def scenario() -> None:
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def runaway(_arguments):
            started.set()
            try:
                await asyncio.Event().wait()  # never set
            except asyncio.CancelledError:
                cancelled.set()
                raise

        gateway = CodexMcpGateway()
        gateway.start()
        credential = gateway.issue("owner", ToolBundle((AgentTool("slow", "", {}, runaway),)))
        try:
            status, result = await asyncio.wait_for(
                asyncio.to_thread(
                    _post,
                    gateway.url,
                    credential.token,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "slow", "arguments": {}},
                    },
                ),
                5,
            )
            assert status == 200
            assert result["result"]["isError"] is True
            await asyncio.wait_for(cancelled.wait(), 1)
        finally:
            gateway.close()

    asyncio.run(scenario())


# ── codex-bus-gateway-race fix (regression pins) ─────────────────────────────
def _bus_bundle():
    return ToolBundle((AgentTool("ask_agent", "delegate", {"type": "object"}, _echo),))


def test_revoke_keeps_server_up_and_url_stable() -> None:
    """Regression: revoking the LAST credential must NOT stop the server, and a
    subsequent issue() must keep the same url — the check-then-act race that left
    a rebuilt codex agent connected to a dead endpoint with zero bus tools."""
    from salient_core.codex_mcp import CodexMcpGateway

    async def scenario() -> None:
        gw = CodexMcpGateway()
        try:
            c1 = gw.issue("manager", _bus_bundle())
            assert gw.running
            url1 = c1.url
            gw.revoke(c1.token)  # last credential gone
            assert gw.running, "server must stay up after last revoke"
            assert gw.url == url1, "url must not change"
            c2 = gw.issue("manager", _bus_bundle())
            assert c2.url == url1, "reissued credential keeps the stable url"
            assert gw.running
        finally:
            gw.close()

    asyncio.run(scenario())


def test_supersede_one_catalog_per_owner() -> None:
    from salient_core.codex_mcp import CodexMcpGateway

    async def scenario() -> None:
        gw = CodexMcpGateway()
        try:
            c1 = gw.issue("manager", _bus_bundle())
            c2 = gw.issue("manager", _bus_bundle())  # supersedes c1
            assert gw._catalog(c1.token) is None
            assert gw._catalog(c2.token) is not None
        finally:
            gw.close()

    asyncio.run(scenario())


def test_revoke_is_idempotent() -> None:
    from salient_core.codex_mcp import CodexMcpGateway

    async def scenario() -> None:
        gw = CodexMcpGateway()
        try:
            c = gw.issue("manager", _bus_bundle())
            gw.revoke(c.token)
            gw.revoke(c.token)  # no-op, must not raise
        finally:
            gw.close()

    asyncio.run(scenario())


def test_wait_attached_returns_once_tools_list_seen() -> None:
    from salient_core.codex_mcp import CodexMcpGateway

    async def scenario() -> None:
        gw = CodexMcpGateway()
        try:
            c = gw.issue("manager", _bus_bundle())
            status, _ = gw._dispatch(
                gw._catalog(c.token), {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
            assert status == 200
            await gw.wait_attached(c.token, timeout=1.0)  # returns fast
        finally:
            gw.close()

    asyncio.run(scenario())


def test_wait_attached_times_out_and_raises() -> None:
    from salient_core.codex_mcp import CodexMcpGateway, GatewayAttachError

    async def scenario() -> None:
        gw = CodexMcpGateway()
        try:
            c = gw.issue("manager", _bus_bundle())
            raised = False
            try:
                await gw.wait_attached(c.token, timeout=0.2)
            except GatewayAttachError:
                raised = True
            assert raised, "must raise GatewayAttachError on attach timeout"
        finally:
            gw.close()

    asyncio.run(scenario())


def test_runner_attach_retry_then_fault() -> None:
    """The runner retries a codex attach failure on its own budget, then FAULTS
    visibly (never runs a silently bus-less agent); a transient failure recovers."""
    from salient_core.codex_mcp import GatewayAttachError
    from salient_core.daemon import AgentRunner
    from salient_core.daemon import runner as runner_mod

    class _FailBackend:
        def __init__(self, fail_times: int) -> None:
            self._left = fail_times

        async def connect(self) -> None:
            if self._left > 0:
                self._left -= 1
                raise GatewayAttachError("manager", "no tools/list")

        async def disconnect(self) -> None:
            return None

    async def scenario() -> None:
        orig = runner_mod._GATEWAY_ATTACH_BACKOFF
        runner_mod._GATEWAY_ATTACH_BACKOFF = (0.0, 0.0)
        try:
            # Exhausts retries -> FAULTED.
            b = _FailBackend(99)
            r = AgentRunner(name="manager", cfg={}, backend_factory=lambda: b)
            r._backend = b
            faulted = False
            try:
                await r._connect_with_attach_retry()
            except GatewayAttachError:
                faulted = True
            assert faulted and r.status == "faulted"

            # Fails once then a fresh backend connects -> recovers.
            seq = iter([_FailBackend(1), _FailBackend(0)])
            r2 = AgentRunner(name="manager", cfg={}, backend_factory=lambda: next(seq))
            r2._backend = _FailBackend(1)
            await r2._connect_with_attach_retry()  # must NOT raise
            assert r2.status != "faulted"
        finally:
            runner_mod._GATEWAY_ATTACH_BACKOFF = orig

    asyncio.run(scenario())
