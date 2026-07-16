from __future__ import annotations

import asyncio
import json
import os
import shlex
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Protocol

from .providers import ProviderCapabilities, ProviderName, ProviderProbe
from .runtime import (
    AgentEvent,
    AssistantEvent,
    ContextUsage,
    JsonValue,
    NativeActionCompletedEvent,
    NativeActionKind,
    NativeActionStartedEvent,
    ProviderErrorEvent,
    TextContent,
    ToolBundle,
    TurnCompletedEvent,
    TurnUsage,
)

_EMPTY_TOOL_BUNDLE = ToolBundle()

# Appended to a codex agent's baseInstructions when it carries bus tools.
# codex >=0.144 hardcodes `tool_search_always_defer_mcp_tools=true`, so the
# salient bus tools are lazy-loaded behind the built-in `tool_search` tool and
# do NOT appear in the model's initial tool list — an agent that just calls
# `ask_agent` sees it "not available". Teach the model to surface them first.
# (Not needed on codex <=0.142, where MCP tools load directly; harmless there.)
_CODEX_BUS_LAZY_LOAD_OVERLAY = (
    "\n\n---\n"
    "TOOL LOADING (codex runtime). ALL of your tools from the `salient` tool "
    "server are LAZY-LOADED and will NOT appear in your initial tool list — both "
    "your task tools (the tool surface described above) AND your coordination "
    "tools: delegation (ask_agent, ask_agents, list_agents), knowledge graph "
    "(kg_assert, kg_query), shared context, and the rest. Before your FIRST use "
    "of any of them, invoke the `tool_search` tool with a query naming what you "
    "need (e.g. `ask_agent delegate to another agent`, or a keyword from the task "
    "tool you want). tool_search returns the matching tool names; call them by "
    "their exact names. If a tool looks unavailable, you have not searched for it "
    "yet — call `tool_search` first; never report a salient tool missing without "
    "searching. Only codex-native tools are available without searching."
)


class CodexUnavailableError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "Codex support is not installed; install the optional 'salient-core[codex]' extra"
        )


class CodexAuthenticationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Codex is not authenticated; run `codex login` or set OPENAI_API_KEY")


# The mcp_servers key under which salient's own bus-tool gateway is registered on
# the codex thread (see CodexProvider.create_backend). Codex gates every MCP tool
# call with an elicitation ("Allow server X to run tool Y?"); for OUR gateway that
# confirmation is redundant — the bus tools enforce salient's scope/safeguard/authz
# gates inside their handlers — so the approval handler auto-accepts it.
SALIENT_MCP_SERVER: Final = "salient"


class ApprovalKind(StrEnum):
    COMMAND = "command"
    FILE_CHANGE = "file_change"
    PERMISSION = "permission"
    UNKNOWN = "unknown"


class ApprovalDecision(StrEnum):
    ACCEPT = "accept"
    DECLINE = "decline"
    CANCEL = "cancel"
    EDIT = "edit"


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    kind: ApprovalKind
    method: str
    item_id: str | None
    reason: str | None
    params: Mapping[str, JsonValue]
    valid: bool
    cancelled: threading.Event

    @classmethod
    def parse(
        cls,
        method: str,
        params: Mapping[str, JsonValue],
        *,
        cancelled: threading.Event | None = None,
    ) -> ApprovalRequest:
        kinds = {
            "item/commandExecution/requestApproval": ApprovalKind.COMMAND,
            "item/fileChange/requestApproval": ApprovalKind.FILE_CHANGE,
            "item/permissions/requestApproval": ApprovalKind.PERMISSION,
        }
        kind = kinds.get(method, ApprovalKind.UNKNOWN)
        item_id = params.get("itemId")
        reason = params.get("reason")
        thread_id = params.get("threadId")
        turn_id = params.get("turnId")
        valid = all(
            isinstance(value, str) and bool(value.strip())
            for value in (item_id, thread_id, turn_id)
        )
        if kind is ApprovalKind.COMMAND:
            valid = valid and bool(params.get("command") or params.get("networkApprovalContext"))
        elif kind is ApprovalKind.FILE_CHANGE:
            valid = valid
        elif kind is ApprovalKind.PERMISSION:
            valid = valid and bool(params.get("permissions"))
        else:
            valid = False
        return cls(
            kind=kind,
            method=method,
            item_id=item_id if isinstance(item_id, str) else None,
            reason=reason if isinstance(reason, str) else None,
            params=dict(params),
            valid=valid,
            cancelled=cancelled or threading.Event(),
        )


FollowupHandler = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    decision: ApprovalDecision
    edited_instruction: str | None = None


ApprovalHandler = Callable[[ApprovalRequest], ApprovalDecision | ApprovalResolution]


def approval_response(
    request: ApprovalRequest,
    decision: ApprovalDecision,
    *,
    edited_instruction: str | None = None,
    followup_handler: FollowupHandler | None = None,
) -> dict[str, JsonValue]:
    """Map Salient's one-shot verdict to the published b3 wire protocol."""
    if not request.valid:
        return {"decision": "decline"}
    if decision is ApprovalDecision.EDIT:
        if edited_instruction and followup_handler is not None:
            followup_handler(edited_instruction)
        return {"decision": "decline"}
    return {"decision": decision.value}


# ── Codex read-only command classifier: safe-flag allowlist ──────────
# Default-deny per-binary flag tables. A Codex-proposed command auto-approves
# (skips the operator gate) only when its binary is known read-only AND every
# flag token is on that binary's safe list. Unknown flags fall through to
# operator approval (classifier returns False) — the safe direction, since a
# false deny only costs a prompt while a false accept auto-executes. Denylists
# rot open as tools grow new flags (rg --pre, git --output/--ext-diff, tail -f
# all slipped a bare-binary allowlist); this allowlist rots closed. Value True =
# the flag consumes the next argv token as a data-only value; False = valueless.
_CODEX_SAFE_FLAGS: dict[str | tuple[str, str], dict[str, bool]] = {
    "ls": {
        "-l": False,
        "-a": False,
        "-h": False,
        "-A": False,
        "-R": False,
        "-t": False,
        "-r": False,
        "-S": False,
        "-1": False,
        "-d": False,
    },
    "grep": {
        "-r": False,
        "-n": False,
        "-i": False,
        "-l": False,
        "-c": False,
        "-v": False,
        "-w": False,
        "-x": False,
        "-F": False,
        "-E": False,
        "-o": False,
        "-H": False,
        "-e": True,
        "-A": True,
        "-B": True,
        "-C": True,
        "--include": True,
        "--exclude": True,
    },
    "rg": {
        "-i": False,
        "-n": False,
        "-l": False,
        "-c": False,
        "-v": False,
        "-w": False,
        "-x": False,
        "-F": False,
        "-S": False,
        "-s": False,
        "-o": False,
        "-e": True,
        "-g": True,
        "-t": True,
        "-A": True,
        "-B": True,
        "-C": True,
        "-m": True,
        "--json": False,
        "--no-heading": False,
        "--hidden": False,
        "--max-columns": True,
    },
    "head": {"-n": True, "-c": True},
    "tail": {"-n": True, "-c": True},
    "cat": {"-n": False, "-A": False, "-b": False},
    "wc": {"-l": False, "-c": False, "-w": False, "-m": False},
    "stat": {"-c": True, "--format": True},
    "pwd": {},
    ("git", "diff"): {
        "--stat": False,
        "--name-only": False,
        "--name-status": False,
        "--cached": False,
        "--staged": False,
        "-U": True,
        "--no-color": False,
    },
    ("git", "log"): {
        "--oneline": False,
        "--stat": False,
        "-n": True,
        "--graph": False,
        "--follow": False,
        "--no-color": False,
        "--format": True,
        "--pretty": True,
        "--since": True,
        "--until": True,
        "--author": True,
        "--grep": True,
    },
    ("git", "show"): {
        "--stat": False,
        "--name-only": False,
        "--no-color": False,
        "--format": True,
        "--pretty": True,
    },
    ("git", "status"): {"-s": False, "--short": False, "--porcelain": False, "-b": False},
}


def _codex_flags_all_safe(table: dict[str, bool], argv: list[str]) -> bool:
    """True when every flag token in argv is on ``table`` (valueless or
    data-valued); positional args (paths/patterns) pass. An unrecognized flag
    returns False (→ operator approval). Bundled shorts (``-lah``) pass only
    when each constituent is a valueless safe flag, so ``tail -fn5`` / ``rg
    -zi`` still deny. A trailing value-taking flag with no value → False."""
    i = 0
    expect_value = False
    while i < len(argv):
        tok = argv[i]
        i += 1
        if expect_value:
            expect_value = False
            continue
        if tok == "--":
            return True  # end of options — the rest are paths/patterns
        if not tok.startswith("-") or tok == "-":
            continue  # positional (path / pattern / stdin)
        flag, _, inline_val = tok.partition("=")
        if flag in table:  # exact long/short flag, optional --flag=value
            expect_value = table[flag] and not inline_val
            continue
        if not flag.startswith("--") and len(flag) > 2:
            head = flag[:2]  # e.g. "-A" of "-A3"
            if head in table and table[head]:
                continue  # value-taking short with glued value, e.g. -A3 / -n50
            if all(f"-{ch}" in table and not table[f"-{ch}"] for ch in flag[1:]):
                continue  # bundle of valueless shorts, e.g. -lah / -rn
        return False
    return not expect_value


def codex_command_is_read_only(params: Mapping[str, Any]) -> bool:
    """Classify a Codex command-approval request as read-only (safe to
    auto-accept without an operator gate). Public seam for downstream skins
    that build their own approval handlers."""
    if params.get("networkApprovalContext"):
        return False
    command = params.get("command")
    if isinstance(command, list):
        if not command or not all(isinstance(part, str) and part for part in command):
            return False
        parts = list(command)
        command_text = " ".join(parts)
    elif isinstance(command, str):
        command_text = command
        try:
            parts = shlex.split(command)
        except ValueError:
            return False
    else:
        return False
    if any(marker in command_text for marker in ("\r", "\n", "&", "|", ";", "<", ">", "$", "`")):
        return False
    if not parts:
        return False
    # Per-binary safe-flag allowlist (default-deny). The `git` global-option
    # slot (parts[1]) must be a read-only subcommand, which already rejects
    # `git -c …` / `git --exec-path …`; the subcommand's own flags are then
    # allowlisted so `git log --output=…` / `git diff --ext-diff` deny.
    if parts[0] == "git":
        if len(parts) < 2 or parts[1] not in {"diff", "log", "show", "status"}:
            return False
        table = _CODEX_SAFE_FLAGS.get(("git", parts[1]))
        return table is not None and _codex_flags_all_safe(table, parts[2:])
    table = _CODEX_SAFE_FLAGS.get(parts[0])
    return table is not None and _codex_flags_all_safe(table, parts[1:])


@dataclass(frozen=True, slots=True)
class CodexBackendConfig:
    cwd: str
    model: str | None = None
    # Reasoning effort passed to the model (codex `model_reasoning_effort`):
    # one of none|minimal|low|medium|high|xhigh. None → the model's default.
    effort: str | None = None
    instructions: str | None = None
    env: Mapping[str, str] | None = None
    mcp_config: Mapping[str, JsonValue] | None = None


class _Model(Protocol):
    def model_dump(self, **kwargs: Any) -> dict[str, Any]: ...


class _CodexClient(Protocol):
    def start(self) -> None: ...
    def initialize(self) -> Any: ...
    def account_read(self, params: Any = None) -> Any: ...
    def account_login_start(self, params: Any) -> Any: ...
    def thread_start(self, params: dict[str, Any]) -> Any: ...
    def turn_start(self, thread_id: str, prompt: str) -> Any: ...
    def next_turn_notification(self, turn_id: str) -> Any: ...
    def unregister_turn_notifications(self, turn_id: str) -> None: ...
    def turn_interrupt(self, thread_id: str, turn_id: str) -> Any: ...
    def close(self) -> None: ...


ClientFactory = Callable[..., _CodexClient]


def _default_client_factory(
    *,
    approval_handler: Callable[[str, dict[str, JsonValue] | None], dict[str, JsonValue]],
    config: CodexBackendConfig,
) -> _CodexClient:
    try:
        from openai_codex.client import CodexClient, CodexConfig
    except ImportError as error:
        raise CodexUnavailableError from error
    env = dict(config.env or {})

    def sdk_approval_handler(method: str, params: Any) -> dict[str, Any]:
        normalized = params if isinstance(params, dict) else None
        return approval_handler(method, normalized)

    client: _CodexClient = CodexClient(
        config=CodexConfig(
            cwd=config.cwd,
            env=env,
            # codex >=0.144 hardcodes `tool_search_always_defer_mcp_tools=true`
            # (stage "removed" in `codex features list` — NOT overridable via
            # --config or the runtime feature-enablement RPC), so external-MCP
            # tools (the salient bus) are lazy-loaded through the `tool_search`
            # tool and surface PREFIXED as `mcp__salient.ask_agent`, etc. Flip
            # `non_prefixed_mcp_tool_names` (stage "under development" — this one
            # IS honored) so tool_search returns the bare names (ask_agent,
            # kg_*, …) the agent prompts already reference. The lazy-load itself
            # is taught to the model via the bus overlay in `create_backend`.
            config_overrides=("features.non_prefixed_mcp_tool_names=true",),
        ),
        approval_handler=sdk_approval_handler,
    )
    return client


def _dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(by_alias=True, exclude_none=True, mode="json")
        return dumped if isinstance(dumped, dict) else {}
    return value if isinstance(value, dict) else {}


def _id(value: Any, parent: str) -> str:
    nested = getattr(value, parent, None)
    identifier = getattr(nested, "id", None)
    if isinstance(identifier, str):
        return identifier
    dumped = _dump(value).get(parent, {})
    return str(dumped.get("id", "")) if isinstance(dumped, dict) else ""


def _tokens(data: Mapping[str, Any]) -> TurnUsage:
    usage = data.get("tokenUsage", data)
    if not isinstance(usage, Mapping):
        return TurnUsage()
    # Per-turn slice ("last") drives the input/output/cache accounting the runner
    # sums each turn; the cumulative slice ("total") drives thread context
    # occupancy (total_tokens) — reporting the per-turn slice there under-counts
    # occupancy so compaction gating never fires. Fall back through last → total
    # → the usage mapping itself for older flat shapes.
    per_turn = usage.get("last")
    cumulative = usage.get("total")
    if not isinstance(per_turn, Mapping):
        per_turn = cumulative if isinstance(cumulative, Mapping) else usage
    if not isinstance(cumulative, Mapping):
        cumulative = per_turn
    input_tokens = int(per_turn.get("inputTokens", 0) or 0)
    output_tokens = int(per_turn.get("outputTokens", 0) or 0)
    cached = int(per_turn.get("cachedInputTokens", 0) or 0)
    reasoning = int(per_turn.get("reasoningOutputTokens", 0) or 0)
    reported_total = cumulative.get("totalTokens")
    window = usage.get("modelContextWindow")
    return TurnUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cached,
        reasoning_tokens=reasoning,
        total_tokens=(
            int(reported_total)
            if isinstance(reported_total, (int, float))
            else int(cumulative.get("inputTokens", 0) or 0)
            + int(cumulative.get("outputTokens", 0) or 0)
        ),
        context_window=int(window) if isinstance(window, (int, float)) else None,
    )


class CodexBackend:
    def __init__(
        self,
        config: CodexBackendConfig,
        *,
        client_factory: ClientFactory = _default_client_factory,
        approval_handler: ApprovalHandler | None = None,
        followup_handler: FollowupHandler | None = None,
        revoke_mcp: Callable[[], None] | None = None,
        attach_check: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._config = config
        self._approval_handler = approval_handler or (lambda _request: ApprovalDecision.DECLINE)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="salient-codex")
        self._client = client_factory(
            config=config,
            approval_handler=self._handle_approval,
        )
        self._thread_id: str | None = None
        self._turn_id: str | None = None
        self._usage = TurnUsage()
        self._closed = False
        self._followup_handler = followup_handler
        self._revoke_mcp = revoke_mcp
        # Confirms codex actually received the bus-tool schemas from the gateway
        # (fail-closed). Set by create_backend ONLY when a gateway credential was
        # issued; None => this agent has no bus tools, nothing to confirm.
        self._attach_check = attach_check
        self._approval_cancellations: set[threading.Event] = set()
        self._approval_lock = threading.Lock()
        self._started_actions: set[str] = set()
        self._completed_actions: set[str] = set()

    async def _run(self, function: Callable[..., Any], *args: Any) -> Any:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, function, *args)

    def _handle_approval(
        self,
        method: str,
        params: dict[str, JsonValue] | None,
    ) -> dict[str, JsonValue]:
        if method == "mcpServer/elicitation/request":
            # Codex gates each MCP tool call with an elicitation
            # ("Allow server X to run tool Y?"). For OUR OWN gateway the
            # confirmation is redundant — the bus tools already enforce salient's
            # scope/safeguard/authz gates in their handlers — so auto-accept and let
            # the real gates apply. Declining (the old unknown-method default)
            # blocked EVERY codex bus tool call before it reached the gateway.
            return self._resolve_mcp_elicitation(params or {})
        cancellation = threading.Event()
        request = ApprovalRequest.parse(method, params or {}, cancelled=cancellation)
        if self._closed:
            return approval_response(request, ApprovalDecision.CANCEL)
        if not request.valid:
            return approval_response(request, ApprovalDecision.DECLINE)
        with self._approval_lock:
            self._approval_cancellations.add(cancellation)
        try:
            resolution = self._approval_handler(request)
        except (TimeoutError, RuntimeError):
            resolution = ApprovalDecision.DECLINE
        finally:
            with self._approval_lock:
                self._approval_cancellations.discard(cancellation)
        if cancellation.is_set():
            return approval_response(request, ApprovalDecision.CANCEL)
        if isinstance(resolution, ApprovalResolution):
            return approval_response(
                request,
                resolution.decision,
                edited_instruction=resolution.edited_instruction,
                followup_handler=self._followup_handler,
            )
        return approval_response(request, resolution)

    def _resolve_mcp_elicitation(self, params: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        # MCP elicitation response shape (ElicitResult): accept | decline | cancel,
        # with `content` matching the requested (here empty) schema. Auto-accept the
        # per-tool-call approval elicitation for OUR gateway; fail closed on any
        # other elicitation (unknown server, non-approval mode) so an external MCP
        # server can't be silently auto-approved.
        meta = params.get("_meta")
        kind = meta.get("codex_approval_kind") if isinstance(meta, Mapping) else None
        server = params.get("serverName")
        if kind == "mcp_tool_call" and server == SALIENT_MCP_SERVER:
            return {"action": "accept", "content": {}}
        return {"action": "decline"}

    async def connect(self) -> None:
        await self._run(self._client.start)
        await self._run(self._client.initialize)
        account = _dump(await self._run(self._client.account_read))
        if not account.get("account"):
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise CodexAuthenticationError
            await self._login_api_key(api_key)
        params: dict[str, Any] = {
            "cwd": str(Path(self._config.cwd).resolve()),
            "ephemeral": True,
            "sandbox": "read-only",
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
        }
        if self._config.model:
            params["model"] = self._config.model
        if self._config.instructions:
            # The baked salient system prompt is this agent's BASE persona — the
            # exact analogue of Claude's ClaudeAgentOptions(system_prompt=...).
            # It must go in `baseInstructions`, which REPLACES codex's built-in
            # "you are Codex" base persona; `developerInstructions` only layers
            # on top of that default, so the model keeps self-identifying as
            # Codex. Salient agents get all tools via MCP (not codex-native
            # shell/apply_patch), so replacing the base persona is safe.
            params["baseInstructions"] = self._config.instructions
        # Merge the reasoning-effort override into the codex config object (the
        # same JsonObject that carries mcp_servers). `model_reasoning_effort`
        # takes none|minimal|low|medium|high|xhigh; unset → the model default.
        config_obj: dict[str, Any] = (
            dict(self._config.mcp_config) if self._config.mcp_config else {}
        )
        if self._config.effort:
            config_obj["model_reasoning_effort"] = self._config.effort
        if config_obj:
            params["config"] = config_obj
        started = await self._run(self._client.thread_start, params)
        self._thread_id = _id(started, "thread")
        # Fail closed: confirm codex actually fetched the bus-tool schemas from
        # the gateway. If it didn't (dead endpoint, bad token, empty schema), the
        # model would silently have NO ask_agent — worse than a visibly failed
        # start for a delegation hub. Revoke the token we minted and raise so the
        # runner retries / faults instead of running bus-less.
        if self._attach_check is not None:
            try:
                await self._attach_check()
            except BaseException:
                if self._revoke_mcp is not None:
                    with suppress(Exception):
                        self._revoke_mcp()
                with suppress(Exception):
                    await self._run(self._client.close)
                raise

    async def _login_api_key(self, api_key: str) -> None:
        try:
            from openai_codex.generated.v2_all import ApiKeyLoginAccountParams, LoginAccountParams
        except ImportError as error:
            raise CodexUnavailableError from error
        params = LoginAccountParams(root=ApiKeyLoginAccountParams(api_key=api_key, type="apiKey"))
        await self._run(self._client.account_login_start, params)

    async def disconnect(self) -> None:
        self._closed = True
        with self._approval_lock:
            pending = tuple(self._approval_cancellations)
        for cancellation in pending:
            cancellation.set()
        deadline = time.monotonic() + 0.5
        while pending and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
            with self._approval_lock:
                pending = tuple(self._approval_cancellations)
        if not pending and self._thread_id and self._turn_id:
            try:
                await self.interrupt()
            except (EOFError, OSError, RuntimeError):
                pass
        await self._run(self._client.close)
        if self._revoke_mcp is not None:
            self._revoke_mcp()
        self._executor.shutdown(wait=not pending, cancel_futures=True)

    async def query(self, prompt: str) -> None:
        if self._thread_id is None:
            raise RuntimeError("Codex backend is not connected")
        started = await self._run(self._client.turn_start, self._thread_id, prompt)
        self._turn_id = _id(started, "turn")

    async def receive_response(self) -> AsyncIterator[AgentEvent]:
        if self._turn_id is None:
            return
        turn_id = self._turn_id
        text_parts: list[str] = []

        def _drain() -> AssistantEvent | None:
            # Coalesce the streamed deltas into ONE assistant event, matching the
            # Claude backend's per-message granularity (it yields one event per
            # complete message block, not per token). Without this the console
            # tail prints a timestamped header line per token. Returns None when
            # there is nothing buffered so callers can `if (e := _drain()): yield e`.
            if not text_parts:
                return None
            text = "".join(text_parts)
            text_parts.clear()
            return AssistantEvent(
                content=(TextContent(text),),
                model=self._config.model or "codex",
            )

        try:
            while True:
                notification = await self._run(self._client.next_turn_notification, turn_id)
                method = str(getattr(notification, "method", ""))
                data = _dump(getattr(notification, "payload", {}))
                if method == "item/agentMessage/delta":
                    # Accumulate only — the full message is emitted once at
                    # `item/completed` (or flushed early on a terminal error).
                    delta = data.get("delta")
                    if isinstance(delta, str) and delta:
                        text_parts.append(delta)
                elif method == "thread/tokenUsage/updated":
                    self._usage = _tokens(data)
                elif method == "item/started":
                    event = _native_event(data, completed=False)
                    if event is not None and event.id not in self._started_actions:
                        self._started_actions.add(event.id)
                        yield event
                elif method == "item/completed":
                    item = data.get("item", data)
                    if isinstance(item, Mapping) and item.get("type") == "agentMessage":
                        # Prefer the authoritative final text (post server-side
                        # normalization) over the concatenated deltas when present;
                        # fall back to the accumulated deltas for a delta-only
                        # message. Draining also clears the buffer, so a later
                        # agentMessage in the same turn starts clean (deltas carry
                        # no item id, so accumulation can't be keyed per item).
                        final_text = item.get("text")
                        if isinstance(final_text, str) and final_text:
                            text_parts[:] = [final_text]
                        if (flushed := _drain()) is not None:
                            yield flushed
                    else:
                        event = _native_event(data, completed=True)
                        if event is not None and event.id not in self._completed_actions:
                            self._completed_actions.add(event.id)
                            yield event
                elif method == "error":
                    # Flush any text streamed before the error so a turn that
                    # fails mid-message still surfaces what arrived.
                    if (flushed := _drain()) is not None:
                        yield flushed
                    # The error shape varies (top-level message, nested error
                    # object, bare code); surface whatever detail is present —
                    # and the raw body as a last resort — rather than a bare
                    # "Codex provider error" that hides the real cause (invalid
                    # model, auth, quota, …).
                    err = data.get("error")
                    if isinstance(err, Mapping):
                        detail = err.get("message") or err.get("code") or json.dumps(dict(err))
                    else:
                        detail = data.get("message") or err or data.get("code")
                    if not detail:
                        detail = f"Codex provider error (raw: {json.dumps(dict(data))[:400]})"
                    yield ProviderErrorEvent(code="codex_error", message=str(detail))
                    # Terminal: an `error` notification may not be followed by a
                    # `turn/completed`, so stop rather than block forever on the
                    # next (never-arriving) notification. The finally-block
                    # unregisters the turn.
                    break
                elif method == "turn/completed":
                    # Safety flush: a normal turn already drained at
                    # `item/completed`, but a turn that completes without one
                    # still surfaces its buffered text.
                    if (flushed := _drain()) is not None:
                        yield flushed
                    turn = data.get("turn", {})
                    turn_data = turn if isinstance(turn, Mapping) else {}
                    status = str(turn_data.get("status", "completed"))
                    if status != "completed":
                        error = turn_data.get("error")
                        yield ProviderErrorEvent(
                            code=f"turn_{status}",
                            message=str(error or f"Codex turn {status}"),
                        )
                    yield TurnCompletedEvent(
                        turns=1,
                        duration_ms=int(turn_data.get("durationMs", 0) or 0),
                        usage=self._usage,
                    )
                    break
        except (EOFError, OSError, RuntimeError) as error:
            # Surface any text buffered before the transport dropped.
            if (flushed := _drain()) is not None:
                yield flushed
            yield ProviderErrorEvent(code="transport_closed", message=str(error), retryable=True)
        finally:
            await self._run(self._client.unregister_turn_notifications, turn_id)
            self._turn_id = None
            self._started_actions.clear()
            self._completed_actions.clear()

    async def interrupt(self) -> None:
        if self._thread_id and self._turn_id:
            await self._run(self._client.turn_interrupt, self._thread_id, self._turn_id)

    async def get_context_usage(self) -> ContextUsage | None:
        if self._usage.total_tokens is None:
            return None
        return ContextUsage(
            used_tokens=self._usage.total_tokens,
            max_tokens=self._usage.context_window or 0,
            percentage=(
                self._usage.total_tokens / self._usage.context_window * 100
                if self._usage.context_window
                else 0.0
            ),
            model=self._config.model,
        )

    def diagnose_failure(
        self,
        agent_name: str,
        error: BaseException,
        stderr_tail: tuple[str, ...],
    ) -> str:
        detail = str(error) or type(error).__name__
        return f"{agent_name}: Codex runtime failed: {detail}"


def _mcp_result_text(result: Any) -> str:
    # McpToolCallResult.content is a list of MCP content blocks; the salient
    # gateway ships a single {"type":"text","text": <json>} block. Join the text
    # blocks for the tool-result event body.
    if not isinstance(result, Mapping):
        return ""
    content = result.get("content")
    if not isinstance(content, list):
        return ""
    parts = [
        str(block.get("text", ""))
        for block in content
        if isinstance(block, Mapping) and block.get("type") == "text"
    ]
    return "\n".join(part for part in parts if part)


def _mcp_tool_event(
    item: Mapping[str, Any], *, completed: bool
) -> NativeActionStartedEvent | NativeActionCompletedEvent:
    # A `mcpToolCall` thread item — an MCP tool the provider ran for the agent
    # (e.g. a codex agent calling a salient bus tool). Surfaced as a native action
    # so the runner publishes tool-call / tool-result events, runs loop detection,
    # and records evidence exactly like a Claude tool use.
    item_id = str(item.get("id", ""))
    tool = str(item.get("tool") or "mcp_tool")
    if not completed:
        raw_args = item.get("arguments")
        arguments = dict(raw_args) if isinstance(raw_args, Mapping) else {}
        return NativeActionStartedEvent(item_id, NativeActionKind.MCP_TOOL, tool, arguments)
    error = item.get("error")
    if isinstance(error, Mapping) and error.get("message"):
        return NativeActionCompletedEvent(
            item_id, NativeActionKind.MCP_TOOL, str(error["message"]), True
        )
    is_error = str(item.get("status")) == "failed"
    return NativeActionCompletedEvent(
        item_id, NativeActionKind.MCP_TOOL, _mcp_result_text(item.get("result")), is_error
    )


def _native_event(
    data: Mapping[str, Any], *, completed: bool
) -> NativeActionStartedEvent | NativeActionCompletedEvent | None:
    item = data.get("item", data)
    if not isinstance(item, Mapping):
        return None
    kind_value = item.get("type")
    if kind_value == "mcpToolCall":
        return _mcp_tool_event(item, completed=completed)
    kinds = {
        "commandExecution": NativeActionKind.COMMAND,
        "fileChange": NativeActionKind.FILE_CHANGE,
        "permissions": NativeActionKind.PERMISSION,
    }
    kind = kinds.get(str(kind_value))
    if kind is None:
        return None
    item_id = str(item.get("id", ""))
    if completed:
        content = item.get("aggregatedOutput", item.get("status", ""))
        return NativeActionCompletedEvent(item_id, kind, str(content))
    arguments = {str(key): value for key, value in item.items() if key not in {"id", "type"}}
    return NativeActionStartedEvent(item_id, kind, str(kind_value), arguments)


class CodexProvider:
    name = ProviderName("codex")
    capabilities = ProviderCapabilities(True, True, True, True)

    def __init__(
        self,
        *,
        client_factory: ClientFactory = _default_client_factory,
        approval_handler: ApprovalHandler | None = None,
        followup_handler: FollowupHandler | None = None,
        gateway: Any | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._approval_handler = approval_handler
        self._followup_handler = followup_handler
        self._gateway = gateway

    async def probe(self) -> ProviderProbe:
        try:
            from openai_codex.client import CodexClient, CodexConfig
        except ImportError:
            return ProviderProbe(False, "install the optional salient-core[codex] extra")

        def inspect_account() -> bool:
            client = CodexClient(
                config=CodexConfig(cwd=os.getcwd()),
                approval_handler=lambda _method, _params: {"decision": "decline"},
            )
            try:
                client.start()
                client.initialize()
                return bool(_dump(client.account_read()).get("account"))
            finally:
                client.close()

        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="salient-codex-probe")
        try:
            loop = asyncio.get_running_loop()
            account_ready = await loop.run_in_executor(executor, inspect_account)
        except (FileNotFoundError, OSError, RuntimeError) as error:
            return ProviderProbe(False, f"Codex runtime probe failed: {error}")
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
        if account_ready:
            return ProviderProbe(True, "openai-codex 0.1.0b3; account session ready")
        if os.environ.get("OPENAI_API_KEY"):
            return ProviderProbe(True, "openai-codex 0.1.0b3; API key available")
        return ProviderProbe(False, "run `codex login` or set OPENAI_API_KEY")

    def create_backend(
        self,
        config: Mapping[str, JsonValue],
        *,
        tool_bundle: ToolBundle = _EMPTY_TOOL_BUNDLE,
        approval_handler: ApprovalHandler | None = None,
        followup_handler: FollowupHandler | None = None,
    ) -> CodexBackend:
        cwd = config.get("cwd", os.getcwd())
        model = config.get("model")
        effort = config.get("effort")
        instructions = config.get("instructions")
        if not isinstance(cwd, str):
            raise TypeError("Codex runtime cwd must be a string")
        if model is not None and not isinstance(model, str):
            raise TypeError("Codex runtime model must be a string")
        if effort is not None and not isinstance(effort, str):
            raise TypeError("Codex runtime effort must be a string")
        if instructions is not None and not isinstance(instructions, str):
            raise TypeError("Codex runtime instructions must be a string")
        from .codex_mcp import translate_external_mcp

        mcp_servers: dict[str, JsonValue] = {}
        external_mcp = config.get("mcp_servers")
        if external_mcp is not None:
            if not isinstance(external_mcp, Mapping):
                raise TypeError("Codex runtime mcp_servers must be a mapping")
            for name, server_config in external_mcp.items():
                if not isinstance(server_config, Mapping):
                    raise TypeError(f"Codex MCP server {name!r} must be a mapping")
                mcp_servers[str(name)] = translate_external_mcp(dict(server_config))
        backend_config = CodexBackendConfig(
            cwd=cwd,
            model=model,
            effort=effort,
            instructions=instructions,
            mcp_config={"mcp_servers": mcp_servers} if mcp_servers else None,
        )
        revoke_mcp: Callable[[], None] | None = None
        attach_check: Callable[[], Awaitable[None]] | None = None
        if tool_bundle.tools:
            from .codex_mcp import get_codex_mcp_gateway

            gateway = self._gateway or get_codex_mcp_gateway()
            credential = gateway.issue(str(config.get("agent_name", "codex")), tool_bundle)
            # Teach the model that its bus tools are lazy-loaded behind
            # `tool_search` (codex >=0.144). Without this, a delegation hub like
            # `manager` reports "ask_agent not available" instead of searching.
            bus_instructions = (instructions or "") + _CODEX_BUS_LAZY_LOAD_OVERLAY
            backend_config = CodexBackendConfig(
                cwd=cwd,
                model=model,
                effort=effort,
                instructions=bus_instructions,
                env={credential.bearer_token_env_var: credential.token},
                mcp_config={
                    "mcp_servers": {**mcp_servers, SALIENT_MCP_SERVER: credential.codex_config()}
                },
            )
            revoke_mcp = lambda: gateway.revoke(credential.token)
            attach_check = lambda: gateway.wait_attached(credential.token)
        return CodexBackend(
            backend_config,
            client_factory=self._client_factory,
            approval_handler=approval_handler or self._approval_handler,
            followup_handler=followup_handler or self._followup_handler,
            revoke_mcp=revoke_mcp,
            attach_check=attach_check,
        )
