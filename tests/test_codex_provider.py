from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from salient_core.providers import ProviderName, builtin_provider_registry
from salient_core.runtime import (
    AgentTool,
    AssistantEvent,
    ProviderErrorEvent,
    ToolBundle,
    TurnCompletedEvent,
)


@dataclass
class _Id:
    id: str


@dataclass
class _Started:
    thread: _Id
    turn: _Id | None = None


@dataclass
class _Notification:
    method: str
    payload: Any


class _Payload:
    def __init__(self, **values: Any) -> None:
        self._values = values

    def model_dump(self, **_kwargs: Any) -> dict[str, Any]:
        return self._values


class _FakeClient:
    def __init__(self, *, approval_handler: Any) -> None:
        self.approval_handler = approval_handler
        self.started = False
        self.closed = False
        self.thread_params: dict[str, Any] = {}
        self.turns: deque[_Notification] = deque()
        self.interrupted: tuple[str, str] | None = None

    def start(self) -> None:
        self.started = True

    def initialize(self) -> None:
        return None

    def account_read(self, _params: Any = None) -> _Payload:
        return _Payload(account={"type": "chatgpt"})

    def thread_start(self, params: dict[str, Any]) -> _Started:
        self.thread_params = params
        return _Started(_Id("thread-1"))

    def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
        self.turns.extend(
            (
                _Notification(
                    "item/agentMessage/delta",
                    _Payload(delta="hello", turnId="turn-1"),
                ),
                _Notification(
                    "thread/tokenUsage/updated",
                    _Payload(
                        tokenUsage={
                            "total": {
                                "inputTokens": 4,
                                "outputTokens": 2,
                                "totalTokens": 6,
                            },
                            "last": {
                                "inputTokens": 4,
                                "outputTokens": 2,
                                "totalTokens": 6,
                            },
                            "modelContextWindow": 100,
                        }
                    ),
                ),
                _Notification(
                    "item/completed",
                    _Payload(item={"id": "message-1", "type": "agentMessage", "text": "hello"}),
                ),
                _Notification(
                    "turn/completed",
                    _Payload(
                        turn={
                            "id": "turn-1",
                            "status": "completed",
                            "durationMs": 37,
                        }
                    ),
                ),
            )
        )
        return _Started(_Id("thread-1"), _Id("turn-1"))

    def next_turn_notification(self, _turn_id: str) -> _Notification:
        return self.turns.popleft()

    def unregister_turn_notifications(self, _turn_id: str) -> None:
        return None

    def turn_interrupt(self, thread_id: str, turn_id: str) -> None:
        self.interrupted = (thread_id, turn_id)

    def close(self) -> None:
        self.closed = True


def test_codex_backend_uses_ephemeral_read_only_thread_and_streams() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    fake: _FakeClient | None = None

    def factory(*, approval_handler: Any, **_kwargs: Any) -> _FakeClient:
        nonlocal fake
        fake = _FakeClient(approval_handler=approval_handler)
        return fake

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp/work", model="gpt-test", instructions="be exact"),
        client_factory=factory,
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        assert fake is not None
        assert fake.thread_params["ephemeral"] is True
        assert fake.thread_params["sandbox"] == "read-only"
        assert fake.thread_params["approvalPolicy"] == "on-request"
        assert fake.thread_params["approvalsReviewer"] == "user"
        # The salient system prompt is the agent's BASE persona and must go in
        # `baseInstructions` (which replaces codex's built-in "you are Codex"
        # persona), NOT `developerInstructions` (which only layers on top).
        assert fake.thread_params["baseInstructions"] == "be exact"
        assert "developerInstructions" not in fake.thread_params
        assert fake.approval_handler("unknown/request", {}) == {"decision": "decline"}

        await backend.query("hello")
        events = [event async for event in backend.receive_response()]
        # Deltas are coalesced into ONE assistant event per message (Claude
        # parity), so the console tail shows one line, not one per token.
        assert isinstance(events[0], AssistantEvent)
        assert events[0].content[0].text == "hello"
        assert isinstance(events[-1], TurnCompletedEvent)
        assert events[-1].usage.total_tokens == 6
        assert events[-1].usage.context_window == 100
        assert events[-1].duration_ms == 37
        assert sum(isinstance(event, AssistantEvent) for event in events) == 1
        context = await backend.get_context_usage()
        assert context is not None
        assert context.percentage == 6.0

        await backend.query("interrupt")
        await backend.interrupt()
        assert fake.interrupted == ("thread-1", "turn-1")
        await backend.disconnect()
        assert fake.closed

    asyncio.run(scenario())


def test_codex_approval_mapping_never_accepts_for_session() -> None:
    from salient_core.codex import (
        ApprovalDecision,
        ApprovalRequest,
        ApprovalResolution,
        CodexBackend,
        CodexBackendConfig,
        approval_response,
    )

    for method in (
        "item/commandExecution/requestApproval",
        "item/fileChange/requestApproval",
        "item/permissions/requestApproval",
    ):
        payload: dict[str, Any] = {
            "itemId": "i1",
            "threadId": "thread-1",
            "turnId": "turn-1",
        }
        if "commandExecution" in method:
            payload["command"] = "pwd"
        if "permissions" in method:
            payload["permissions"] = ["network"]
        request = ApprovalRequest.parse(method, payload)
        assert approval_response(request, ApprovalDecision.ACCEPT) == {"decision": "accept"}
        assert approval_response(request, ApprovalDecision.DECLINE) == {"decision": "decline"}
        assert approval_response(request, ApprovalDecision.CANCEL) == {"decision": "cancel"}

    unknown = ApprovalRequest.parse("future/request", {})
    assert approval_response(unknown, ApprovalDecision.ACCEPT) == {"decision": "decline"}
    malformed = ApprovalRequest.parse("item/commandExecution/requestApproval", {})
    assert approval_response(malformed, ApprovalDecision.ACCEPT) == {"decision": "decline"}

    network_only = ApprovalRequest.parse(
        "item/commandExecution/requestApproval",
        {
            "itemId": "network-command",
            "threadId": "thread-1",
            "turnId": "turn-1",
            "networkApprovalContext": {"host": "example.com"},
        },
    )
    assert network_only.valid

    followups: list[str] = []
    fake = _FakeClient(approval_handler=lambda _method, _params: {})
    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **_kw: fake,
        approval_handler=lambda _request: ApprovalResolution(
            ApprovalDecision.EDIT, "use a safer command"
        ),
        followup_handler=followups.append,
    )
    assert fake.approval_handler is not None
    assert backend._handle_approval(  # noqa: SLF001
        "item/commandExecution/requestApproval",
        {
            "itemId": "i2",
            "threadId": "thread-1",
            "turnId": "turn-1",
            "command": "touch result.txt",
        },
    ) == {"decision": "decline"}
    assert followups == ["use a safer command"]


def test_codex_auto_accepts_mcp_tool_call_elicitation_for_own_gateway() -> None:
    # Codex gates every MCP tool call with an elicitation ("Allow server X to run
    # tool Y?"). For salient's OWN gateway this is redundant (the bus tools enforce
    # salient's gates in their handlers), so the handler must ACCEPT — otherwise the
    # old unknown-method default declined it and blocked every codex bus tool call.
    from salient_core.codex import (
        SALIENT_MCP_SERVER,
        ApprovalDecision,
        CodexBackend,
        CodexBackendConfig,
    )

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: _FakeClient(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    def _elicit(server: str, kind: str) -> dict[str, Any]:
        return {
            "serverName": server,
            "mode": "form",
            "_meta": {"codex_approval_kind": kind},
            "message": f'Allow the {server} MCP server to run tool "list_agents"?',
            "requestedSchema": {"type": "object", "properties": {}},
        }

    # Our gateway's tool-call approval → accept (empty content for the empty schema).
    assert backend._handle_approval(
        "mcpServer/elicitation/request", _elicit(SALIENT_MCP_SERVER, "mcp_tool_call")
    ) == {"action": "accept", "content": {}}

    # A different (external) MCP server → fail closed.
    assert backend._handle_approval(
        "mcpServer/elicitation/request", _elicit("some_external", "mcp_tool_call")
    ) == {"action": "decline"}

    # A non-tool-call elicitation on our server → fail closed.
    assert backend._handle_approval(
        "mcpServer/elicitation/request", _elicit(SALIENT_MCP_SERVER, "something_else")
    ) == {"action": "decline"}


def test_disconnect_cancels_pending_approval_without_reader_deadlock() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    entered = threading.Event()

    def blocked(request):
        entered.set()
        while not request.cancelled.is_set():
            time.sleep(0.01)
        return ApprovalDecision.CANCEL

    fake = _FakeClient(approval_handler=lambda _method, _params: {})
    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **_kwargs: fake,
        approval_handler=blocked,
    )

    async def scenario() -> None:
        await backend.connect()
        approval = asyncio.create_task(
            asyncio.to_thread(
                backend._handle_approval,  # noqa: SLF001
                "item/commandExecution/requestApproval",
                {
                    "itemId": "pending-command",
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "command": "touch /tmp/x",
                },
            )
        )
        assert await asyncio.to_thread(entered.wait, 1)
        await asyncio.wait_for(backend.disconnect(), timeout=1)
        assert await asyncio.wait_for(approval, timeout=1) == {"decision": "cancel"}

    asyncio.run(scenario())


def test_builtin_registry_keeps_codex_optional() -> None:
    registry = builtin_provider_registry()
    names = {provider.name for provider in registry.providers()}
    assert ProviderName("claude") in names
    assert ProviderName("codex") in names
    codex = registry.get(ProviderName("codex"))
    assert codex.capabilities.streaming


def test_codex_provider_passes_isolated_mcp_credential_and_revokes() -> None:
    from salient_core.codex import CodexProvider

    issued: list[tuple[str, ToolBundle]] = []
    revoked: list[str] = []
    observed_config: list[Any] = []

    class Credential:
        token = "secret-token"
        bearer_token_env_var = "SALIENT_CODEX_MCP_TOKEN"

        @staticmethod
        def codex_config() -> dict[str, Any]:
            return {
                "url": "http://127.0.0.1:1234/mcp",
                "bearer_token_env_var": "SALIENT_CODEX_MCP_TOKEN",
            }

    class Gateway:
        def issue(self, owner: str, bundle: ToolBundle) -> Credential:
            issued.append((owner, bundle))
            return Credential()

        def revoke(self, token: str) -> None:
            revoked.append(token)

        async def wait_attached(self, token: str, timeout: float = 25.0) -> None:
            return None  # fake gateway: attach is instantaneous

    async def handler(arguments):
        return arguments

    bundle = ToolBundle((AgentTool("only-this-agent", "", {}, handler),))

    def factory(**kwargs: Any) -> _FakeClient:
        observed_config.append(kwargs["config"])
        return _FakeClient(approval_handler=kwargs["approval_handler"])

    backend = CodexProvider(client_factory=factory, gateway=Gateway()).create_backend(
        {"agent_name": "agent-a", "cwd": "/tmp"}, tool_bundle=bundle
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.disconnect()

    asyncio.run(scenario())
    assert issued == [("agent-a", bundle)]
    assert observed_config[0].env == {"SALIENT_CODEX_MCP_TOKEN": "secret-token"}
    assert (
        observed_config[0]
        .mcp_config["mcp_servers"]["salient"]["url"]
        .startswith("http://127.0.0.1:")
    )
    assert revoked == ["secret-token"]


def _capture_bus_backend_config(*, instructions: str | None, has_tools: bool) -> Any:
    """Build a backend via CodexProvider and return the CodexBackendConfig the
    client factory observed (its `.instructions` carry any appended overlay)."""
    from salient_core.codex import CodexProvider

    class Credential:
        token = "t"
        bearer_token_env_var = "SALIENT_CODEX_MCP_TOKEN"

        @staticmethod
        def codex_config() -> dict[str, Any]:
            return {
                "url": "http://127.0.0.1:1/mcp",
                "bearer_token_env_var": "SALIENT_CODEX_MCP_TOKEN",
            }

    class Gateway:
        def issue(self, owner: str, bundle: ToolBundle) -> Credential:
            return Credential()

        def revoke(self, token: str) -> None:
            return None

        async def wait_attached(self, token: str, timeout: float = 25.0) -> None:
            return None

    observed: list[Any] = []

    def factory(**kwargs: Any) -> _FakeClient:
        observed.append(kwargs["config"])
        return _FakeClient(approval_handler=kwargs["approval_handler"])

    async def handler(arguments):
        return arguments

    bundle = ToolBundle((AgentTool("ask_agent", "", {}, handler),)) if has_tools else ToolBundle()
    cfg: dict[str, Any] = {"agent_name": "manager", "cwd": "/tmp"}
    if instructions is not None:
        cfg["instructions"] = instructions
    backend = CodexProvider(client_factory=factory, gateway=Gateway()).create_backend(
        cfg, tool_bundle=bundle
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.disconnect()

    asyncio.run(scenario())
    return observed[0]


def test_codex_bus_agent_instructions_teach_tool_search_lazy_load() -> None:
    """codex >=0.144 hard-defers MCP tools behind `tool_search`, so a bus agent
    must be told to search before delegating — otherwise it reports "ask_agent
    not available". The overlay is appended to the agent's own instructions."""
    from salient_core.codex import _CODEX_BUS_LAZY_LOAD_OVERLAY

    observed = _capture_bus_backend_config(instructions="You coordinate.", has_tools=True)
    assert observed.instructions is not None
    assert observed.instructions.startswith("You coordinate.")
    assert _CODEX_BUS_LAZY_LOAD_OVERLAY in observed.instructions
    assert "tool_search" in observed.instructions
    assert "ask_agent" in observed.instructions


def test_codex_non_bus_agent_gets_no_lazy_load_overlay() -> None:
    """An agent with no bus tools has nothing deferred — no overlay noise."""
    from salient_core.codex import _CODEX_BUS_LAZY_LOAD_OVERLAY

    observed = _capture_bus_backend_config(instructions="Be exact.", has_tools=False)
    assert observed.instructions == "Be exact."
    assert _CODEX_BUS_LAZY_LOAD_OVERLAY not in (observed.instructions or "")


def test_default_client_factory_requests_bare_mcp_tool_names() -> None:
    """The deferred bus tools surface PREFIXED (`mcp__salient.ask_agent`) unless
    `non_prefixed_mcp_tool_names` is flipped — flip it so tool_search returns the
    bare names the prompts reference. (This flag IS honored; the defer flag is
    not.)"""
    from salient_core.codex import CodexBackendConfig, _default_client_factory

    def approve(_m: str, _p: Any) -> dict[str, Any]:
        return {"decision": "decline"}

    client = _default_client_factory(
        approval_handler=approve, config=CodexBackendConfig(cwd="/tmp")
    )
    assert "features.non_prefixed_mcp_tool_names=true" in client.config.config_overrides


def test_daemon_codex_approval_uses_operator_inbox_verdicts() -> None:
    from salient_core.codex import ApprovalDecision, ApprovalRequest, ApprovalResolution
    from salient_core.daemon._runner_factory import _RunnerFactoryMixin

    class Harness(_RunnerFactoryMixin):
        answer = "yes"
        profile: dict[str, Any] = {}
        scope = None
        runners: dict[str, Any] = {}
        questions = 0

        def add_tool_approval_question(self, *_args: Any) -> tuple[int, asyncio.Future[Any]]:
            self.questions += 1
            future = asyncio.get_running_loop().create_future()
            future.set_result(self.answer)
            return 42, future

    request = ApprovalRequest.parse(
        "item/commandExecution/requestApproval",
        {
            "itemId": "command-1",
            "threadId": "thread-1",
            "turnId": "turn-1",
            "command": "touch result.txt",
            "cwd": "/tmp",
        },
    )

    async def scenario() -> None:
        harness = Harness()
        assert await harness._resolve_codex_approval("agent", request) is ApprovalDecision.ACCEPT
        assert harness.questions == 1
        harness.answer = "no unsafe"
        assert await harness._resolve_codex_approval("agent", request) is ApprovalDecision.DECLINE
        harness.answer = "edit: use git status"
        edited = await harness._resolve_codex_approval("agent", request)
        assert isinstance(edited, ApprovalResolution)
        assert edited.decision is ApprovalDecision.EDIT
        assert edited.edited_instruction == "use git status"

    asyncio.run(scenario())


def test_daemon_codex_safe_read_is_accepted_without_q_inbox() -> None:
    from salient_core.codex import ApprovalDecision, ApprovalRequest
    from salient_core.daemon._runner_factory import _RunnerFactoryMixin

    class Harness(_RunnerFactoryMixin):
        profile: dict[str, Any] = {}
        scope = None
        runners: dict[str, Any] = {}

        def add_tool_approval_question(self, *_args: Any) -> tuple[int, asyncio.Future[Any]]:
            raise AssertionError("safe read reached Q inbox")

    request = ApprovalRequest.parse(
        "item/commandExecution/requestApproval",
        {
            "itemId": "safe-read",
            "threadId": "thread-1",
            "turnId": "turn-1",
            "command": "git status --short",
        },
    )

    async def scenario() -> None:
        assert await Harness()._resolve_codex_approval("agent", request) is ApprovalDecision.ACCEPT

    asyncio.run(scenario())


def test_codex_safe_read_classifier_rejects_shell_composition() -> None:
    from salient_core.daemon._runner_factory import _RunnerFactoryMixin

    assert _RunnerFactoryMixin._codex_command_is_read_only({"command": "cat 'safe file'"})
    assert _RunnerFactoryMixin._codex_command_is_read_only(
        {"command": ["git", "status", "--short"]}
    )
    for command in (
        "cat x\nrm -rf /",
        "cat x\rrm -rf /",
        "cat x & rm -rf /",
        "cat x | sh",
        "cat x; rm -rf /",
        "cat x > output",
        "cat < input",
        "cat $(touch owned)",
        "cat `touch owned`",
        "git status\nchmod 777 secret",
        "cat $HOME/.ssh/id_rsa",
    ):
        assert not _RunnerFactoryMixin._codex_command_is_read_only({"command": command})


def test_codex_safe_read_classifier_rejects_flag_abuse() -> None:
    from salient_core.daemon._runner_factory import _RunnerFactoryMixin

    read_only = _RunnerFactoryMixin._codex_command_is_read_only
    # Allowlisted binaries with dangerous flags must NOT auto-approve — they
    # fall through to the operator gate (return False). `command` may be a
    # shell string or an argv list; both ride under {"command": ...}.
    for command in (
        # ripgrep --pre runs an arbitrary program per file
        "rg --pre /bin/sh pattern file",
        "rg --pre=/bin/sh pattern file",
        ["rg", "--pre", "/bin/sh", "pattern", "file"],
        "rg --search-zip pattern archive.gz",
        "rg -zi pattern archive.gz",  # bundled short containing -z
        # git flag abuse: writes files / runs external programs / alters config
        "git log --output=/tmp/owned",
        "git log --output /tmp/owned",
        "git diff --ext-diff",
        ["git", "-c", "core.pager=touch owned", "status"],
        "git --exec-path=/tmp log",
        # never-terminating follow
        "tail -f /tmp/fifo",
        "tail --follow /tmp/fifo",
        "tail -fn5 /tmp/fifo",  # bundled short containing -f
        # unknown flag on an allowlisted binary → operator prompt, not auto-run
        "ls --totally-unknown-flag",
    ):
        assert not read_only({"command": command}), command

    # Benign read-only invocations with ordinary flags still auto-approve.
    for command in (
        "cat -n file",
        "ls -la",
        "ls -lah dir",
        "grep -rn pattern .",
        "grep -A3 -B3 pattern file",
        "rg -i pattern",
        "rg -n --json pattern",
        "head -n 50 file",
        "tail -n 5 file",
        "wc -l file",
        "git diff --stat",
        "git log --oneline -n 20",
        ["git", "status", "--short"],
    ):
        assert read_only({"command": command}), command


def test_daemon_codex_predenies_outside_file_and_full_access_permission() -> None:
    from salient_core.codex import ApprovalDecision, ApprovalRequest
    from salient_core.daemon._runner_factory import _RunnerFactoryMixin

    class Harness(_RunnerFactoryMixin):
        profile: dict[str, Any] = {}
        scope = None
        runners: dict[str, Any] = {}
        engagement_path = "/tmp/salient-workspace"

        def add_tool_approval_question(self, *_args: Any) -> tuple[int, asyncio.Future[Any]]:
            raise AssertionError("pre-denied action reached Q inbox")

    file_request = ApprovalRequest.parse(
        "item/fileChange/requestApproval",
        {
            "itemId": "outside-file",
            "threadId": "thread-1",
            "turnId": "turn-1",
            "grantRoot": "/etc",
        },
    )
    permission_request = ApprovalRequest.parse(
        "item/permissions/requestApproval",
        {
            "itemId": "full-access",
            "threadId": "thread-1",
            "turnId": "turn-1",
            "permissions": ["danger-full-access"],
        },
    )

    async def scenario() -> None:
        harness = Harness()
        assert (
            await harness._resolve_codex_approval("agent", file_request) is ApprovalDecision.DECLINE
        )
        assert (
            await harness._resolve_codex_approval("agent", permission_request)
            is ApprovalDecision.DECLINE
        )

    asyncio.run(scenario())


def test_daemon_codex_approval_safeguard_predeny_skips_q_inbox() -> None:
    from salient_core.codex import ApprovalDecision, ApprovalRequest
    from salient_core.daemon._runner_factory import _RunnerFactoryMixin
    from salient_core.policy.defaults import DEFAULT_DATASET
    from salient_core.policy.registry import PolicyDataset, set_active

    class Harness(_RunnerFactoryMixin):
        profile: dict[str, Any] = {}
        scope = None
        runners: dict[str, Any] = {}
        questions = 0

        def add_tool_approval_question(self, *_args: Any) -> tuple[int, asyncio.Future[Any]]:
            self.questions += 1
            raise AssertionError("pre-denied command reached Q inbox")

    denied = PolicyDataset(
        tool_targets=DEFAULT_DATASET.tool_targets,
        prohibited_patterns={
            **DEFAULT_DATASET.prohibited_patterns,
            "bash.run": (("blocked", "deny-me"),),
        },
        loud_patterns=DEFAULT_DATASET.loud_patterns,
        natural_language_prohibited=DEFAULT_DATASET.natural_language_prohibited,
    )
    request = ApprovalRequest.parse(
        "item/commandExecution/requestApproval",
        {
            "itemId": "blocked-command",
            "threadId": "thread-1",
            "turnId": "turn-1",
            "command": "deny-me",
        },
    )

    async def scenario() -> None:
        harness = Harness()
        try:
            set_active(denied)
            assert (
                await harness._resolve_codex_approval("agent", request) is ApprovalDecision.DECLINE
            )
            assert harness.questions == 0
        finally:
            set_active(DEFAULT_DATASET)

    asyncio.run(scenario())


def test_codex_transport_failure_is_normalized() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    class Broken(_FakeClient):
        def next_turn_notification(self, _turn_id: str) -> _Notification:
            raise EOFError("closed")

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: Broken(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("x")
        events = [event async for event in backend.receive_response()]
        assert len(events) == 1
        assert isinstance(events[0], ProviderErrorEvent)
        await backend.disconnect()

    asyncio.run(scenario())


def test_codex_final_only_message_and_failed_turn_are_normalized() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    class Failed(_FakeClient):
        def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
            self.turns.extend(
                (
                    _Notification(
                        "item/completed",
                        _Payload(
                            item={"id": "message-final", "type": "agentMessage", "text": "final"}
                        ),
                    ),
                    _Notification(
                        "turn/completed",
                        _Payload(
                            turn={
                                "id": "turn-failed",
                                "status": "failed",
                                "durationMs": 91,
                                "error": {"message": "model failed"},
                            }
                        ),
                    ),
                )
            )
            return _Started(_Id("thread-1"), _Id("turn-failed"))

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: Failed(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("x")
        events = [event async for event in backend.receive_response()]
        assert isinstance(events[0], AssistantEvent)
        assert events[0].content[0].text == "final"
        assert isinstance(events[1], ProviderErrorEvent)
        assert events[1].code == "turn_failed"
        assert isinstance(events[2], TurnCompletedEvent)
        assert events[2].duration_ms == 91
        await backend.disconnect()

    asyncio.run(scenario())


def test_codex_native_action_replay_is_exactly_once() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig
    from salient_core.runtime import NativeActionCompletedEvent, NativeActionStartedEvent

    class Replayed(_FakeClient):
        def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
            started = _Notification(
                "item/started",
                _Payload(
                    item={
                        "id": "command-replayed",
                        "type": "commandExecution",
                        "command": "pwd",
                    }
                ),
            )
            completed = _Notification(
                "item/completed",
                _Payload(
                    item={
                        "id": "command-replayed",
                        "type": "commandExecution",
                        "status": "completed",
                    }
                ),
            )
            self.turns.extend(
                (
                    started,
                    started,
                    completed,
                    completed,
                    _Notification(
                        "turn/completed",
                        _Payload(turn={"id": "turn-replay", "status": "completed"}),
                    ),
                )
            )
            return _Started(_Id("thread-1"), _Id("turn-replay"))

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: Replayed(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("x")
        events = [event async for event in backend.receive_response()]
        assert sum(isinstance(event, NativeActionStartedEvent) for event in events) == 1
        assert sum(isinstance(event, NativeActionCompletedEvent) for event in events) == 1
        await backend.disconnect()

    asyncio.run(scenario())


def test_codex_mcp_tool_call_surfaces_as_native_action() -> None:
    # An MCP tool call (a codex agent calling a salient bus tool through the
    # gateway) must surface as NativeAction start/complete so the runner publishes
    # tool-call / tool-result events — otherwise codex tool use is invisible in the
    # operator event log while text turns show.
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig
    from salient_core.runtime import (
        NativeActionCompletedEvent,
        NativeActionKind,
        NativeActionStartedEvent,
    )

    class _McpCall(_FakeClient):
        def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
            self.turns.extend(
                (
                    _Notification(
                        "item/started",
                        _Payload(
                            item={
                                "id": "mcp-1",
                                "type": "mcpToolCall",
                                "server": "salient",
                                "tool": "list_agents",
                                "arguments": {"filter": ""},
                            }
                        ),
                    ),
                    _Notification(
                        "item/completed",
                        _Payload(
                            item={
                                "id": "mcp-1",
                                "type": "mcpToolCall",
                                "server": "salient",
                                "tool": "list_agents",
                                "status": "completed",
                                "result": {
                                    "content": [{"type": "text", "text": "manager  status=idle"}]
                                },
                            }
                        ),
                    ),
                    _Notification(
                        "turn/completed",
                        _Payload(turn={"id": "turn-1", "status": "completed"}),
                    ),
                )
            )
            return _Started(_Id("thread-1"), _Id("turn-1"))

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: _McpCall(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("x")
        events = [event async for event in backend.receive_response()]
        started = [e for e in events if isinstance(e, NativeActionStartedEvent)]
        completed = [e for e in events if isinstance(e, NativeActionCompletedEvent)]
        assert len(started) == 1 and len(completed) == 1
        # The event carries the TOOL name (not "mcpToolCall") + MCP_TOOL kind + args.
        assert started[0].name == "list_agents"
        assert started[0].kind is NativeActionKind.MCP_TOOL
        assert dict(started[0].arguments) == {"filter": ""}
        assert completed[0].kind is NativeActionKind.MCP_TOOL
        assert completed[0].is_error is False
        assert "manager  status=idle" in completed[0].content
        await backend.disconnect()

    asyncio.run(scenario())


def test_codex_deltas_coalesce_into_one_final_message() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    class _Streamed(_FakeClient):
        def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
            self.turns.extend(
                (
                    _Notification("item/agentMessage/delta", _Payload(delta="hel")),
                    _Notification("item/agentMessage/delta", _Payload(delta="lo")),
                    _Notification(
                        "item/completed",
                        _Payload(item={"id": "m1", "type": "agentMessage", "text": "hello"}),
                    ),
                    _Notification(
                        "turn/completed",
                        _Payload(turn={"id": "turn-1", "status": "completed"}),
                    ),
                )
            )
            return _Started(_Id("thread-1"), _Id("turn-1"))

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: _Streamed(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("x")
        events = [event async for event in backend.receive_response()]
        # The two deltas are coalesced into exactly ONE assistant event carrying
        # the authoritative final text — not one event per delta.
        assistant = [e for e in events if isinstance(e, AssistantEvent)]
        assert len(assistant) == 1
        assert assistant[0].content[0].text == "hello"
        await backend.disconnect()

    asyncio.run(scenario())


def test_codex_two_agent_messages_per_turn_do_not_contaminate() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    class _TwoMessages(_FakeClient):
        def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
            self.turns.extend(
                (
                    _Notification("item/agentMessage/delta", _Payload(delta="first message")),
                    _Notification(
                        "item/completed",
                        _Payload(
                            item={"id": "m1", "type": "agentMessage", "text": "first message"}
                        ),
                    ),
                    _Notification("item/agentMessage/delta", _Payload(delta="second")),
                    _Notification(
                        "item/completed",
                        _Payload(
                            item={"id": "m2", "type": "agentMessage", "text": "second message"}
                        ),
                    ),
                    _Notification(
                        "turn/completed",
                        _Payload(turn={"id": "turn-1", "status": "completed"}),
                    ),
                )
            )
            return _Started(_Id("thread-1"), _Id("turn-1"))

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: _TwoMessages(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("x")
        events = [event async for event in backend.receive_response()]
        # Each message drains + clears independently, so the second message's
        # text never carries the first's buffered deltas.
        assistant = [e for e in events if isinstance(e, AssistantEvent)]
        assert [e.content[0].text for e in assistant] == ["first message", "second message"]
        await backend.disconnect()

    asyncio.run(scenario())


def test_codex_error_mid_message_flushes_buffered_text() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    class _ErrorMidStream(_FakeClient):
        def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
            # Deltas arrive, then the turn errors before `item/completed`. The
            # buffered text must still be surfaced, ahead of the error event.
            self.turns.extend(
                (
                    _Notification("item/agentMessage/delta", _Payload(delta="partial ")),
                    _Notification("item/agentMessage/delta", _Payload(delta="answer")),
                    _Notification("error", _Payload(message="boom")),
                )
            )
            return _Started(_Id("thread-1"), _Id("turn-1"))

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp"),
        client_factory=lambda **kw: _ErrorMidStream(approval_handler=kw["approval_handler"]),
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("x")
        events = [event async for event in backend.receive_response()]
        assert isinstance(events[0], AssistantEvent)
        assert events[0].content[0].text == "partial answer"
        assert isinstance(events[1], ProviderErrorEvent)
        assert events[1].code == "codex_error"
        await backend.disconnect()

    asyncio.run(scenario())


def test_codex_tokens_uses_cumulative_total_and_accepts_float() -> None:
    from salient_core.codex import _tokens

    usage = _tokens(
        {
            "tokenUsage": {
                "last": {"inputTokens": 3, "outputTokens": 1, "totalTokens": 4},
                "total": {"inputTokens": 30, "outputTokens": 10, "totalTokens": 40.0},
                "modelContextWindow": 100,
            }
        }
    )
    # Per-turn input/output come from `last`; context occupancy from `total`,
    # and a float totalTokens is honored (not discarded).
    assert usage.input_tokens == 3
    assert usage.output_tokens == 1
    assert usage.total_tokens == 40
    assert usage.context_window == 100


def test_codex_error_notification_terminates_without_turn_completed() -> None:
    from salient_core.codex import ApprovalDecision, CodexBackend, CodexBackendConfig

    class _ErrorOnlyClient(_FakeClient):
        def turn_start(self, _thread_id: str, _prompt: str) -> _Started:
            # A single `error` notification and NOTHING after it. If the receive
            # loop failed to break, the next popleft() on the empty deque would
            # raise IndexError (uncaught) and fail this test.
            self.turns.append(
                _Notification("error", _Payload(message="boom")),
            )
            return _Started(_Id("thread-1"), _Id("turn-1"))

    fake: _ErrorOnlyClient | None = None

    def factory(*, approval_handler: Any, **_kwargs: Any) -> _ErrorOnlyClient:
        nonlocal fake
        fake = _ErrorOnlyClient(approval_handler=approval_handler)
        return fake

    backend = CodexBackend(
        CodexBackendConfig(cwd="/tmp/work"),
        client_factory=factory,
        approval_handler=lambda _request: ApprovalDecision.DECLINE,
    )

    async def scenario() -> None:
        await backend.connect()
        await backend.query("hello")
        events = [event async for event in backend.receive_response()]
        assert len(events) == 1
        assert isinstance(events[0], ProviderErrorEvent)
        assert events[0].code == "codex_error"

    asyncio.run(scenario())
