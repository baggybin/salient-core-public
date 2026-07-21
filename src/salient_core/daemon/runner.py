"""Per-agent runner — owns one AgentBackend task and its job queue.

`AgentRunner` is the self-contained execution unit: it drives an
`AgentBackend` supplied by the daemon's provider factory, consumes a prompt
queue, streams normalized response
blocks (text / thinking / tool-use / tool-result), emits structured
events to subscribers + JSONL, tracks token + cost + refusal counters,
and enforces the per-agent loop-detection + safeguard halt gates.

`Daemon._make_runner` constructs an `AgentRunner` for each named agent and
back-injects references to its shared services — `context`, `_scope_store`,
`_action_ledger`, `_event_hub`, `_engagement_path`, `_on_loop_detected` —
plus a back-reference to the daemon itself (`_daemon`). The runner DOES
reach back through `_daemon`, but only for the bounded set of operations
pinned by the `DaemonServices` Protocol below (filing operator questions,
context/KG writes, profile + inbox reads). It never imports the `Daemon`
class (only a `TYPE_CHECKING` forward ref), so the import direction stays
one-way: daemon → runner.
"""

import asyncio
import copy
import functools
import hashlib
import json
import logging
import os
import time
from collections import Counter, deque
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, assert_never

import anyio

_log = logging.getLogger("salient.daemon.runner")

# Sentinel pushed onto the job queue to wake an idle _run loop when an operator
# steer lands in the priority lane (asyncio.Queue has no front-insert). The loop
# ignores it and re-checks the lane.
_STEER_WAKE = object()

# Auto-recovery from OAuth-rotation 401s. The daemon's long-lived SDK
# subprocesses share one ~/.claude/.credentials.json; when another `claude`
# process refreshes the shared OAuth token it rotates the (single-use) token
# out from under a long-lived subprocess, which then gets a 401
# (sdk_error=authentication_failed) on its NEXT turn and stays dead-in-place
# until reset. On that specific error the runner re-spawns its SDK client once
# — a fresh subprocess re-reads the rotated, now-valid credential — and re-runs
# the job. Scoped to authentication_failed only: rate_limit / server_error /
# billing_error need backoff or operator action, not a reconnect.
_AUTH_RECOVER_ERRORS = frozenset({"authentication_failed"})
_MAX_AUTH_RECOVERIES = 1
_AUTH_RECOVER_BACKOFF = 2.0  # seconds — let any in-flight token refresh settle

# Bounded retry for a codex bus-gateway attach failure — its OWN budget, kept
# separate from the auth-401 recovery above so a wedged gateway can't burn (or be
# mis-attributed to) the auth budget. On exhaustion the runner FAULTS visibly
# rather than run a delegation agent that silently lacks ask_agent.
_MAX_GATEWAY_ATTACH_RETRIES = 2
_GATEWAY_ATTACH_BACKOFF = (1.0, 5.0)  # seconds, per retry

# Stopwords for the task-start skill-hint matcher (_render_skills_hint_block).
# IDF down-weights tokens that are common ACROSS THE SKILL LIBRARY, but it has
# no notion of general-English frequency, so a word that's common in prose yet
# rare in the corpus ("for", "write") still scores as informative. This is the
# textbook companion to IDF — strip the function/framing words IDF can't know
# about; specific security terms (which also tend to co-occur in real tasks)
# carry the signal. Kept deliberately generic (no security terms) so it never
# suppresses a real match.
_SKILL_HINT_STOPWORDS = frozenset(
    """
a an and are any as at be been being but by can could did do does done for from
get got had has have her here his how into its just let like make made may might
more most need not now off only onto our out over per please should some such than
that the their them then there these they this those through too try use using very
want was were what when where which while who why will with would you your
write writes writing wrote read note notes report reports reporting summary summaries
summarise summarize document draft email message send paragraph executive about above
below also each both
""".split()
)

from ..bus import ContextStore, _redact_secret_fields
from ..codex_mcp import GatewayAttachError
from ..display import (
    _emit,
    _format_tool_args,
    _format_tool_result,
    _prettify_tool_name,
    _truncate,
)
from ..memory.actions import extract_target_keys_from_text, target_key_for_call
from ..memory.credentials import cred_kinds, predicate_for_kind
from ..policy.decision import ToolInvocation, text_identity
from ..policy.registry import PolicyDataset, get_active
from ..policy.safeguards import (
    OperatorPromptMode,
    OperatorPromptModeError,
    SafeguardConfig,
    check_prompt_intent,
    resolve_config,
)
from ..policy.scope import ScopeStore
from ..protocols import AgentBackend, DaemonServices
from ..runtime import (
    AssistantEvent,
    ContextCompactedEvent,
    MissingBackendError,
    NativeActionCompletedEvent,
    NativeActionStartedEvent,
    ProviderErrorEvent,
    TextContent,
    ThinkingContent,
    ToolBundle,
    ToolCallContent,
    ToolResultEvent,
    TurnCompletedEvent,
)
from ._event_hub import fork_event
from ._helpers import (
    _TEXT_FULL_INLINE_CAP,
    DEFAULT_HISTORY_MAX,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_PROMPT_TIMEOUT,
    DEFAULT_TAIL_BUFFER,
    Job,
    classify_run_loop_error,
)
from ._prompts import (
    _extract_function_calls_from_text,
    _strip_llama_output_noise,
)
from ._text_policy import authorize_text


async def _offload_blocking_io(
    func: Callable[..., Any],
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    if kwargs:
        return await anyio.to_thread.run_sync(functools.partial(func, **kwargs), *args)
    return await anyio.to_thread.run_sync(func, *args)


@dataclass
class AgentRunner:
    name: str
    cfg: dict[str, Any]
    backend_factory: Callable[[], AgentBackend] | None = None
    tool_bundle: ToolBundle = field(default_factory=ToolBundle)
    prompt_timeout: float = DEFAULT_PROMPT_TIMEOUT
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT
    context: ContextStore | None = None
    tail_buffer_size: int = DEFAULT_TAIL_BUFFER
    on_job_complete: Callable[["AgentRunner", "Job"], None] | None = None
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    # Completed-job history. Bounded to the most-recent `history_max` jobs so a
    # long-lived runner can't grow it without limit; the full record persists
    # to the jobs table. `jobs_recorded` keeps the true lifetime count (seeded
    # at construction + 1 per append) for the `completed=` displays, since
    # len(history) now caps. Reads other than that count use only the tail.
    history: list[Job] = field(default_factory=list)
    history_max: int = DEFAULT_HISTORY_MAX
    jobs_recorded: int = 0
    current: Job | None = None
    status: str = "starting"
    last_active: float = field(default_factory=time.time)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    recent_events: deque = field(default_factory=deque)
    # The agent SDK backend the runner drives, constructed by the selected
    # provider factory.
    _backend: AgentBackend | None = None
    _task: asyncio.Task | None = None
    _stop_requested: bool = False
    _next_job_id: int = 1
    _next_seq: int = 1
    # Cumulative token usage across this runner's lifetime. Reset by
    # `salientctl reset <agent>` (which destroys+recreates the runner).
    # `last_input_tokens` approximates the conversation's CURRENT context
    # size — what got sent to the model at the start of the most recent
    # turn — useful for "is this agent getting heavy?" decisions.
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cache_read_tokens: int = 0
    total_cache_create_tokens: int = 0
    total_cost_usd: float = 0.0
    total_jobs_completed: int = 0
    # Count of detected Anthropic Usage-Policy / API-error refusals. Each
    # occurrence emits a structured 'refusal' event to the agent's JSONL
    # with the job prompt, model, recent tool calls, and the refusal text
    # so the operator can triage what's triggering it. Visible via
    # `info <agent>` and `logs grep refusal`.
    total_refusals: int = 0
    # Count of tool calls refused by salient.safeguards (prohibited-use
    # pattern matches). When this reaches the halt_threshold (default 3,
    # per-agent or per-engagement override), the runner refuses ALL
    # further tool calls until the operator resets the agent — gives one
    # false-positive trip without dooming the engagement.
    total_safeguard_blocks: int = 0
    total_prompt_hard_blocks: int = 0
    last_input_tokens: int = 0
    last_output_tokens: int = 0
    # Tokens accumulated since the last checkpoint (manual or auto). Used
    # by the auto-checkpoint heuristic: when this exceeds the threshold
    # configured via SALIENT_AUTO_CHECKPOINT_TOKENS, the daemon's
    # _on_job_complete hook logs a warning (and optionally fires
    # _cmd_checkpoint(name, reset=True) when SALIENT_AUTO_CHECKPOINT_ENABLED=1).
    # Counted as in + cache_create + cache_read = total prompt tokens per
    # turn, which tracks "context size" rather than "cost." Reset to 0
    # when /checkpoint or /reset destroys+recreates the runner.
    _tokens_since_checkpoint: int = 0
    # True while a checkpoint reflection step is submitting its own jobs to this
    # runner — read by _check_auto_checkpoint to avoid recursing (a reflection
    # job completing must not trigger ANOTHER auto-checkpoint).
    _reflecting: bool = False
    # True only while a turn is actually in flight (the receive_response loop in
    # _process). steer(interrupt=True) checks THIS — not `current is not None` —
    # so a steer in the post-turn finalization window (current still set, no turn
    # streaming) doesn't fire a spurious interrupt.
    _turn_active: bool = False
    # Set by steer() when it interrupts a live turn; consumed by _process's
    # silent-completion check so a steer-truncated turn isn't re-prompted by the
    # nudge (same role cap_fired plays for the hard-cap path).
    _steer_interrupt_pending: bool = False
    # Set by _maybe_log_refusal when a turn fails with
    # sdk_error=authentication_failed (the OAuth-rotation signal). Consumed by
    # _dispatch_job, which reconnects the SDK client once and re-runs the job.
    # Reset to False before every attempt.
    _auth_recover_pending: bool = False
    # SDK's authoritative context-usage snapshot from the last successful
    # call to client.get_context_usage(). When present, _usage_for prefers
    # these values over the heuristic (which may be off when memory files
    # / MCP tools / agents take significant context).
    last_context_usage: dict[str, Any] | None = None
    # Loop-detection: bounded ring of recent (tool_name, args_hash) pairs,
    # checked on every ToolUseBlock. When the same tuple repeats >=
    # threshold times within window, file an <ask_operator> question and
    # clear the deque so we don't spam. Configured per-agent via
    # `loop_detection_window` / `loop_detection_threshold` /
    # `loop_detection_ignore_patterns` / `loop_detection_ignore_tools`
    # in agents.yaml. There is intentionally no engagement-profile
    # fallback path — AgentRunner doesn't carry a profile reference, and
    # past prose to that effect was aspirational. If a global override
    # is wanted, thread the profile dict into runner construction and
    # add an explicit fallback in __post_init__ + _check_loop.
    _recent_tool_calls: deque = field(default_factory=deque)
    # (tool_name, arg_hash) keys we've already filed a loop question for. The
    # detector clears `_recent_tool_calls` when it fires, so a genuinely stuck
    # call would otherwise re-hit the threshold and re-file every few repeats —
    # spamming the operator. Report each (tool, args) loop ONCE per agent.
    _loop_reported: set = field(default_factory=set)
    # Cumulative per-tool-name call count. Surfaced via `info <agent>`
    # so the operator can see what the agent is actually using (tells
    # you whether the agent is leaning on its specialty tools or
    # falling back to bash/run a lot, which is usually a smell).
    tool_call_counts: Counter = field(default_factory=Counter)
    # Lazy-opened append-mode handle for <engagement>/logs/<agent>.jsonl.
    # Each event passes through _log_jsonl as a structured record so
    # `salientctl logs grep` can search across runs without scraping the
    # terminal stream. None when no engagement_path is set.
    _jsonl_fh: Any = None
    # Log-write modes ("jsonl" / "evidence") that have already emitted their
    # first-failure warning. Persistent logging failures (disk full, perms)
    # are swallowed so they never crash an agent, but we warn ONCE per mode
    # so the operator isn't blind to a silently dropped log; further failures
    # in that mode stay quiet to avoid log spam.
    _log_warned: set[str] = field(default_factory=set)
    # Scope store reference — used to render the live "Active scope" block
    # into every task message body, so the agent sees the authoritative
    # rule set on each turn rather than having to ask the operator. Stored
    # behind a validating property (below) so a wrong-typed store fails loudly
    # at assignment instead of silently degrading to "scope unconfigured".
    _scope_store_ref: "ScopeStore | None" = field(default=None, repr=False, compare=False)
    _policy_dataset: PolicyDataset | None = field(default=None, repr=False, compare=False)
    _safeguard_config: SafeguardConfig = field(
        default_factory=SafeguardConfig,
        repr=False,
        compare=False,
    )
    _enforce_builtin_policy: bool = field(default=False, repr=False, compare=False)
    # Action ledger reference — every ToolUseBlock records a row, every
    # ToolResultBlock fills in the outcome. Lets the daemon inject a
    # "Prior actions" block on each new task and gives the bus a
    # `prior_actions` tool agents can query mid-task.
    _action_ledger: Any = None
    # Back-reference to the daemon, injected by `_make_runner`. Used by
    # endpoint-override agents whose local model emits OpenAI-style
    # function-call JSON in plain text: _dispatch_text_function_calls routes
    # recognized calls to their real daemon handlers (add_question,
    # context.write, kg.assert_fact, inbox.get). The accessed surface is
    # bounded by the `DaemonServices` Protocol above. repr/compare are OFF
    # because `_daemon` points back at the Daemon that owns this runner — a
    # recursive structure the dataclass repr/eq must not walk.
    _daemon: "DaemonServices | None" = field(default=None, repr=False, compare=False)
    _legacy_trusted_builtin_warned: set[str] = field(
        default_factory=set,
        repr=False,
        compare=False,
    )
    _legacy_trusted_builtin_warning_lock: anyio.Lock = field(
        default_factory=anyio.Lock,
        repr=False,
        compare=False,
    )
    # Idempotency guard for cancel_job: the id of the in-flight job we've already
    # fired an interrupt into, so two independent reap owners (an operator `bus
    # cancel` and the ask_agent timeout reaper targeting the same child) can't
    # double-interrupt one turn. Resets naturally when a new job becomes
    # `current` (a different id).
    _interrupted_job_id: int | None = field(default=None, repr=False, compare=False)
    # Daemon-wide event hub — _publish mirrors every event to the global
    # /ws/events/all stream (not just the per-agent tail).
    _event_hub: Any = field(default=None, repr=False, compare=False)  # EventHub
    # Per-incarnation epoch — a monotonic daemon-lifetime int stamped by
    # _make_runner onto every event this runner publishes. `seq` is per-runner
    # and RESETS when a same-name runner is torn down + rebuilt, so a consumer
    # replaying the hub ring (which outlives the old incarnation) after a
    # rebuild would see the old `(agent, seq)` and SUPPRESS a live event with
    # the same seq from the new incarnation. Deduping on `(agent, epoch, seq)`
    # closes that gap. 0 for a runner the factory never stamped.
    _epoch: int = 0
    # Engagement root, so the runner can write evidence + JSONL log files.
    _engagement_path: Any = None  # pathlib.Path | None
    # Loop-detection callback (Daemon._on_loop_detected). Sync — called from
    # inside the runner's async _check_loop; just files an operator question.
    _on_loop_detected: "Callable[[Any, str, int, str], None] | None" = field(
        default=None, repr=False, compare=False
    )
    # sha256 of the agent's resolved prompt-file body (prompts/<name>.md),
    # stamped by _make_runner for prompt-drift provenance (`prompt_diff`).
    _prompt_sha: str = ""
    # tool_use_id → ledger row id, populated on ToolUseBlock so the
    # matching ToolResultBlock can finish the row. Trimmed in-place
    # when rows are finished; capped at 256 entries to bound memory
    # if a tool_use ever fires without a paired result.
    _inflight_actions: dict[str, int] = field(default_factory=dict)
    # Per-dispatch turn counter — incremented on every AssistantMessage
    # inside _process; reset to 0 at job start. Exposed as a runner
    # field (not just a _process local) so the PreToolUse budget-chip
    # hook can read it on each tool call to inject "[budget: N/M]"
    # context. Pre-2026-05-16 this was a `_process`-scoped local.
    current_turn_count: int = 0
    # When the runner calls `client.interrupt()` for its own reasons
    # (prompt_timeout, hard-cap, stop(kill=True)), the SDK echoes back
    # a synthetic ToolResultBlock with the stock string "The user
    # doesn't want to proceed with this tool use..." — which falsely
    # implicates the operator. This field carries the runner's actual
    # reason so the ToolResultBlock handler can rewrite the display
    # to "[RUNNER TIMEOUT after Xs — operator did NOT reject]" etc.
    # Cleared after one rewrite so a genuine operator rejection later
    # in the same job isn't mis-attributed.
    _last_interrupt_reason: str | None = None
    # Wall-clock timestamp of the most recent agent activity. Used by
    # the per-job idle watchdog (see `_run` and `_idle_watchdog`) so
    # `prompt_timeout` behaves as MAX IDLE TIME rather than max total
    # runtime. Tool execution doesn't update this — but while a tool
    # is in flight (`_inflight_actions` non-empty) the watchdog skips
    # the idle check, so long-running tools (full sweeps, large batch
    # jobs) don't eat the budget. Updated by `_publish` on every
    # event the agent emits.
    _last_activity_ts: float = 0.0
    # tool_use_id → (tool_name, arg_hash) for calls currently in the
    # loop-detection ring. When a ToolResultBlock comes back as a
    # deterministic gate refusal (e.g. "pending operator question"),
    # the matching ring entry is popped so the agent's retry after the
    # gate clears doesn't look like a loop. Capped at 256 to bound
    # memory if any tool_use ever fires without a paired result.
    _loop_ring_index: dict[str, tuple] = field(default_factory=dict)
    # Rolling tail of the SDK CLI subprocess's stderr. The factory
    # wires a callback into ClaudeAgentOptions(stderr=...) that pushes
    # each line into this deque; the SDK pipes stderr to PIPE only
    # when such a callback is provided (see SDK
    # _internal/transport/subprocess_cli.py). The buffer is read by
    # the run-loop catch site via classify_run_loop_error: when the
    # subprocess dies, the trailing lines are folded into the operator-
    # facing tool-error message so the actual CLI failure (npm error,
    # model rejection, ANTHROPIC_API_KEY rejected, etc.) is visible
    # instead of just the SDK's wrapped exception. Capped at 200 lines
    # which bounds worst-case memory to a few hundred KB per agent.
    stderr_buffer: deque = field(default_factory=lambda: deque(maxlen=200))

    def __post_init__(self) -> None:
        # Bound the ring buffer at construction time.
        self.recent_events = deque(self.recent_events, maxlen=self.tail_buffer_size)
        # Loop-detection ring is bounded by the configured window (default 8).
        win = int((self.cfg or {}).get("loop_detection_window", 8))
        self._recent_tool_calls = deque(maxlen=max(2, win))
        # Operator-steer priority lane: messages here run ahead of the FIFO
        # queue at the next turn boundary (see steer() + _run).
        self._steer_lane: deque = deque()

    def _create_backend(self) -> AgentBackend:
        if self.backend_factory is not None:
            return self.backend_factory()
        raise MissingBackendError(self.name)

    @property
    def _scope_store(self) -> "ScopeStore | None":
        return self._scope_store_ref

    @_scope_store.setter
    def _scope_store(self, store: "ScopeStore | None") -> None:
        # Validate at the injection boundary: a non-None value that is not a
        # ScopeStore (stale import, a mock leaking into prod, a refactored class)
        # must NOT be silently coerced to None downstream — that would turn a
        # config bug into a policy bypass. Fail loudly here instead.
        if store is not None and not isinstance(store, ScopeStore):
            raise TypeError(
                f"{self.name!r} runner scope store must be a ScopeStore or None, "
                f"got {type(store).__name__}; refusing to silently treat a "
                "misconfigured scope store as unconfigured"
            )
        self._scope_store_ref = store

    def subscribe(self) -> tuple[asyncio.Queue, list[dict[str, Any]]]:
        """Subscribe to live events and get a snapshot of recent ones.

        Order matters: append the queue first, then snapshot. That way any
        event that races between the two operations is captured by both
        paths; the ``seq`` field lets the consumer dedupe.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self.subscribers.append(q)
        # Fork each frame: the ring keeps the canonical event; this subscriber
        # gets deeply-isolated copies it can annotate without corrupting the
        # ring, another subscriber, or a later replay.
        snapshot = [fork_event(evt) for evt in self.recent_events]
        return q, snapshot

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with suppress(ValueError):
            self.subscribers.remove(q)

    def _record_job_history(self, job: "Job") -> None:
        """Append a completed job to history, bump the lifetime counter, and
        bound the in-memory list to `history_max`. The jobs table keeps the
        full record; reads other than the `jobs_recorded` count use only the
        recent tail (history[-N:]), so trimming oldest-first is transparent."""
        self.history.append(job)
        self.jobs_recorded += 1
        # Trim oldest-first. Use an explicit count (not [:-history_max]) so
        # history_max == 0 correctly clears rather than no-opping (-0 == 0).
        if len(self.history) > self.history_max:
            del self.history[: len(self.history) - self.history_max]

    def _publish(
        self, kind: str, text: str, *, text_full: str | None = None, meta: dict | None = None
    ) -> None:
        # Idle-watchdog heartbeat: every published event counts as
        # agent activity. Tool execution doesn't publish here (the
        # SDK runs tools internally), so long tools are handled
        # separately by the watchdog's `_inflight_actions` check.
        self._last_activity_ts = time.time()
        evt: dict[str, Any] = {
            "agent": self.name,
            "kind": kind,
            "text": text,
            "ts": time.time(),
            "epoch": self._epoch,
            "seq": self._next_seq,
        }
        # Job attribution: tag the event with the currently-processing job's
        # id so a delegated-stream consumer (ask_agent's echo pump) can isolate
        # THIS job's events from other callers' work interleaved on the same
        # runner. Omitted when no job is in flight (idle / banner / start).
        cur = self.current
        if cur is not None:
            evt["job_id"] = cur.id
        if meta:
            # Structured fields the web pane uses to render rich
            # cards for known event subkinds (e.g. bus_ask_agent
            # → source/target chips + collapsible prompt body).
            # Falls through to the plain text path on the CLI side.
            #
            # Deep-copy at birth: this ONE event dict is aliased into three
            # fan-out targets sharing the same nested `meta` — recent_events,
            # the hub ring, and every subscriber queue. Severing the producer's
            # reference here means a caller that reuses or mutates its `meta`
            # dict after _publish can't retroactively rewrite already-recorded
            # history (replayed events would otherwise show post-hoc state).
            # Guarded: _publish runs on the AGENT's hot path and must never
            # raise, so a non-copyable value (lock, handle, coroutine) degrades
            # to a shallow copy — which still severs the top-level alias — with
            # a warning, rather than taking down the producing agent.
            try:
                evt["meta"] = copy.deepcopy(meta)
            except Exception:  # noqa: BLE001 — observability must not crash the agent
                _log.warning("meta deepcopy failed for %s/%s; using shallow copy", self.name, kind)
                evt["meta"] = {**meta}
        # Optional full-text payload — only attached when the display
        # text was truncated (`text_full != text`) AND the full body
        # fits under the inline-expand cap. The web console uses this
        # to make the `... [+N chars]` marker clickable: click expands
        # the line in place using `text_full`. Larger payloads fall
        # back to the existing "logs grep / read_evidence" workflow.
        if text_full is not None and text_full != text and len(text_full) <= _TEXT_FULL_INLINE_CAP:
            evt["text_full"] = text_full
        self._next_seq += 1
        # Always record to the ring buffer so a tailer that connects later
        # can replay the backlog, even if no one was subscribed at the time.
        self.recent_events.append(evt)
        for q in list(self.subscribers):
            try:
                # Fork per subscriber: the ring keeps the canonical birth event;
                # each consumer gets a deeply-isolated copy so annotating one
                # subscriber's frame can't corrupt another's or a later replay.
                q.put_nowait(fork_event(evt))
            except asyncio.QueueFull:
                # Drop on backpressure — slow tailer shouldn't block the agent.
                pass
        # Daemon-wide tap: feed the same event to the global hub (if the
        # daemon injected one) so /ws/events/all streams every agent, not
        # just those with an open pane. Same drop-on-full backpressure.
        hub = getattr(self, "_event_hub", None)
        if hub is not None:
            hub.publish(evt)

    async def _log(self, kind: str, text: str, *, meta: dict | None = None) -> None:
        await _emit(self.name, kind, text)
        self._publish(kind, text, meta=meta)
        # Mirror to the per-agent JSONL so `salientctl logs grep` can find
        # it later. tool-call / tool-result events are emitted separately
        # in _process with the full structured payload (input dict, full
        # text) — those don't go through _log to avoid duplication.
        if kind not in ("tool-call", "tool-result", "tool-error"):
            await self._record_jsonl(kind, {"text": text})

    async def _log_provenance(
        self,
        kind: str,
        body: str,
        *,
        source: str,
        recipient: str | None = None,
        qid: int | None = None,
        extras: dict[str, Any] | None = None,
    ) -> None:
        """Persist a provenance event (user_message / peer_message /
        operator_answer) AND surface it on the agent's live stream so
        the web console pane shows "[operator] …" / "[from manager] …"
        with a timestamp inline alongside text/tool events — not just
        buried in <agent>.jsonl after the fact.

        Pre-2026-05-16 the three call sites only wrote to JSONL + SQL,
        so the operator could grep history but couldn't see incoming
        prompts/delegations in real time. This helper bundles the
        persistence write with a `_publish` of the formatted prefix +
        truncated body, with `text_full` attached for inline expand
        when the body fits under the standard cap.

        `recipient` defaults to self.name (this runner). `qid` is set
        for operator_answer events so the prefix carries the Q-id.
        `extras` lets callers add fields to the JSONL/SQL payload
        without affecting display formatting."""
        DISPLAY_LIMIT = 400
        if kind == "user_message":
            prefix = "[operator]"
        elif kind == "peer_message":
            prefix = f"[from {source}]"
        elif kind == "operator_answer":
            qchip = f" Q{qid}" if qid is not None else ""
            prefix = f"[operator answer{qchip}]"
        else:
            prefix = f"[{source}]"
        # JSONL/SQL payload — carries everything the audit replay needs.
        payload: dict[str, Any] = {"text": body}
        if extras:
            payload.update(extras)
        await self._record_jsonl(
            kind,
            payload,
            source=source,
            recipient=recipient or self.name,
        )
        # Display line — prefix + body, truncated to keep the pane scannable.
        body_disp = (body or "").strip()
        if len(body_disp) <= DISPLAY_LIMIT:
            display = f"{prefix} {body_disp}"
            full = None
        else:
            display = (
                f"{prefix} {body_disp[:DISPLAY_LIMIT]}… [+{len(body_disp) - DISPLAY_LIMIT} chars]"
            )
            full = f"{prefix} {body_disp}"
        await _emit(self.name, kind, display)
        self._publish(kind, display, text_full=full)

    async def _log_truncated(
        self,
        kind: str,
        full_text: str,
        limit: int,
        *,
        meta: dict | None = None,
    ) -> None:
        """_log a body that may be too long for the operator-visible
        terminal log. Truncates for display (matching the existing
        `... [+N chars]` marker shape) and attaches the FULL text to
        the published event when it fits under _TEXT_FULL_INLINE_CAP,
        so the web console can render the marker as a clickable
        expand button.

        Behavior:
          - len(full_text) <= limit  → identical to `_log(kind, full_text)`.
          - over limit, under cap    → event carries `text` (truncated) +
                                        `text_full` (full). Web expands inline.
          - over limit, over cap     → event carries only `text` (truncated).
                                        Marker stays non-clickable; operator
                                        uses `salientctl logs grep` /
                                        read_evidence / context_grep instead.

        Caller behavior unchanged from the prior `_log(_truncate(...))`
        pattern at the call sites. We still emit the truncated form to
        the terminal _emit path because the daemon's own stdout is
        line-wrapped and the operator's eye can't usefully scan a
        100-line tool-result dumped inline."""
        full_text = full_text.strip()
        if len(full_text) <= limit:
            await self._log(kind, full_text, meta=meta)
            return
        truncated = full_text[:limit] + f"... [+{len(full_text) - limit} chars]"
        await _emit(self.name, kind, truncated)
        self._publish(kind, truncated, text_full=full_text, meta=meta)
        if kind not in ("tool-call", "tool-result", "tool-error"):
            await self._record_jsonl(kind, {"text": full_text})

    async def _check_loop(
        self,
        tool_name: str,
        tool_input: Any,
        tool_use_id: str | None = None,
    ) -> None:
        """Detect when the agent calls the same tool with the same args
        repeatedly within the configured window. On threshold breach, file
        an <ask_operator> question and clear the deque so we don't spam.
        Operator's reply (stop / continue / adjust) arrives as the agent's
        next prompt — natural escape hatch.

        Read-only / polling tools are exempted by suffix pattern — calling
        `agent_tasks`/`job_list`/`session_list` repeatedly is the natural
        polling pattern for async frameworks, NOT a stuck
        loop. Per-agent override via `loop_detection_ignore_patterns` and
        `loop_detection_ignore_tools` in cfg.

        `tool_use_id` is recorded in `_loop_ring_index` so the matching
        ToolResultBlock can retroactively pop this entry from the ring
        if the call gets refused by a deterministic gate (pending
        operator question, etc.). Retry-after-gate-clears is correct
        agent behavior; the detector shouldn't fire on that pattern.
        See `_pop_loop_entry_on_gate_refusal` for the pop side."""
        # Pattern-based exemption: read-only / polling tool names. `_read` covers
        # `context_read`, which swarm workers legitimately poll while waiting for
        # peers to write shared findings — hammering a side-effect-free read is a
        # normal wait pattern, not a stuck loop, and the per-turn cap already bounds
        # runaway polling. (A mutating tool named `*_read` would be a naming bug;
        # tighten via the per-agent `loop_detection_ignore_patterns` override.)
        cfg = self.cfg or {}
        default_patterns = ("_list", "_tasks", "_info", "_status", "_get", "_read")
        patterns = tuple(cfg.get("loop_detection_ignore_patterns") or default_patterns)
        ignore_tools = set(cfg.get("loop_detection_ignore_tools") or ())
        # Strip the MCP wrapper prefix for matching: mcp__server__tool → tool
        bare = tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name
        if bare in ignore_tools or any(bare.endswith(p) for p in patterns):
            return
        try:
            arg_hash = hashlib.sha1(
                json.dumps(tool_input, sort_keys=True, default=str).encode()
            ).hexdigest()[:12]
        except Exception:
            return  # malformed input, can't hash — skip silently
        key = (tool_name, arg_hash)
        self._recent_tool_calls.append(key)
        if tool_use_id is not None:
            self._loop_ring_index[tool_use_id] = key
            # Bound memory if any tool_use ever fires without a paired
            # ToolResultBlock — drop the oldest entry. Same heuristic
            # as _inflight_actions.
            if len(self._loop_ring_index) > 256:
                drop_key = next(iter(self._loop_ring_index))
                self._loop_ring_index.pop(drop_key, None)
        threshold = int(cfg.get("loop_detection_threshold", 3))
        if threshold <= 1:
            return  # disabled
        repeats = sum(1 for k in self._recent_tool_calls if k == key)
        on_loop = getattr(self, "_on_loop_detected", None)
        # In-memory check first (per-runner, recent calls). When it fires,
        # short-circuit so we don't ALSO file the cross-job question for
        # the same call.
        if repeats >= threshold:
            self._recent_tool_calls.clear()
            if on_loop is None:
                return
            if not self._mark_loop_reported(key):
                return  # already surfaced this (tool, args) loop once — don't spam
            try:
                await _emit(
                    self.name,
                    "loop",
                    f"loop suspected: {tool_name} called {repeats}x with same args "
                    f"(hash {arg_hash}) — filing operator question",
                )
                on_loop(self, tool_name, repeats, arg_hash)
            except Exception:
                pass
            return
        # Cross-job / cross-agent ledger check. The in-memory deque misses
        # two cases: (a) the agent did >window other things between repeats,
        # (b) a different agent already ran this same (tool, args) earlier
        # in the engagement. The ledger catches both.
        #
        # The current call has NOT been recorded yet (action_ledger_start
        # runs after _check_loop), so prior_count is exactly "how many
        # identical calls happened before this one". If prior_count + 1
        # (this call) ≥ threshold, fire.
        pretty = bare  # already mcp__ stripped
        ledger = getattr(self, "_action_ledger", None)
        if ledger is None:
            return
        try:
            window_min = float(cfg.get("cross_job_loop_window_minutes", 30))
            since_ts = time.time() - window_min * 60.0
            prior = ledger.count_recent(
                tool=pretty,
                args_hash=arg_hash,
                since_ts=since_ts,
            )
        except Exception:
            return
        if prior + 1 < threshold:
            return
        if on_loop is None:
            return
        if not self._mark_loop_reported(key):
            return  # already surfaced this (tool, args) loop once — don't spam
        try:
            await _emit(
                self.name,
                "loop",
                f"cross-engagement loop suspected: {pretty} with hash "
                f"{arg_hash} already ran {prior}× in the last "
                f"{int(window_min)}min engagement-wide — filing operator "
                f"question",
            )
            on_loop(self, tool_name, prior + 1, arg_hash)
        except Exception:
            pass

    def _mark_loop_reported(self, key: tuple[str, str]) -> bool:
        """Return True the FIRST time a (tool, arg_hash) loop is reported for this
        agent, False thereafter — so the operator hears about a given stuck call
        once, not on every threshold-th repeat. Bounded so a pathological agent
        can't grow the set without limit."""
        if key in self._loop_reported:
            return False
        self._loop_reported.add(key)
        if len(self._loop_reported) > 512:
            self._loop_reported.pop()
        return True

    # Substrings in a tool-result that mark a deterministic, non-loop
    # refusal: the bus / scope / safeguard layer pre-empted the call,
    # and the agent's retry after the operator clears the gate is
    # correct behavior — not a stuck thought-loop. Matched
    # case-insensitively in `_pop_loop_entry_on_gate_refusal`.
    _LOOP_GATE_REFUSAL_MARKERS: tuple[str, ...] = (
        "pending operator question",  # bus._conflicting_pending_question gate
    )

    def _pop_loop_entry_on_gate_refusal(
        self,
        tool_use_id: str,
        result_text: str,
    ) -> None:
        """When a ToolResultBlock comes back as a deterministic
        gate-refusal error, remove the matching entry from the loop-
        detection ring. Without this, an agent that correctly retries
        an `ask_agent` after the operator clears the blocking question
        looks identical to a stuck thought-loop (three identical
        calls in a row) — and trips a spurious "loop suspected"
        question. Reported live 2026-05-16; see test_loop_gate_*."""
        key = self._loop_ring_index.pop(tool_use_id, None)
        if key is None:
            return
        lower = (result_text or "").lower()
        if not any(m in lower for m in self._LOOP_GATE_REFUSAL_MARKERS):
            return
        # Remove the most-recent matching entry from the deque. Walk
        # right-to-left so we drop *this* call's entry (the most
        # recent), not an earlier identical one that legitimately
        # contributes to the loop window.
        try:
            items = list(self._recent_tool_calls)
            for i in range(len(items) - 1, -1, -1):
                if items[i] == key:
                    del items[i]
                    break
            else:
                return
            self._recent_tool_calls.clear()
            self._recent_tool_calls.extend(items)
        except Exception:
            # Ring mutation is best-effort; never crash the runner
            # over a loop-detection bookkeeping failure.
            pass

    def _warn_log_failure(self, mode: str, exc: BaseException) -> None:
        """Warn once per log-write mode that a write was dropped, then stay
        quiet. Keeps the never-crash-the-agent contract while making a
        silently failing log destination visible to the operator."""
        if mode in self._log_warned:
            return
        self._log_warned.add(mode)
        _log.warning(
            "[%s] %s log write failed (dropping; silencing further warnings for this mode): %r",
            self.name,
            mode,
            exc,
        )

    def _save_evidence(self, job: "Job", kind: str, text: str) -> None:
        """Append untruncated tool output to the engagement evidence dir."""
        eng = getattr(self, "_engagement_path", None)
        if eng is None:
            return
        path = eng / "evidence" / f"{self.name}_{job.id}_{kind}.txt"
        try:
            with path.open("a") as fh:
                fh.write(text.rstrip() + "\n\n")
            # Untruncated tool output (may include credential-search
            # results) — owner-only at rest; dir 0700 covers siblings too.
            os.chmod(path, 0o600)
            os.chmod(path.parent, 0o700)
        except OSError as e:
            self._warn_log_failure("evidence", e)

    async def _action_ledger_start(
        self,
        job: "Job",
        block: ToolCallContent,
        pretty: str,
    ) -> None:
        """Record a started tool call. tool_use_id → row-id is stashed
        on the runner so the paired ToolResultBlock can finish the row.
        Best-effort: any failure here MUST NOT crash the agent — logging
        failures already swallow, and this is the same shape.

        The blocking SQLite write is offloaded to a thread (the store's RLock
        keeps it safe); the in-memory `_inflight_actions` bookkeeping stays on
        the loop."""
        ledger = getattr(self, "_action_ledger", None)
        if ledger is None:
            return
        try:
            tk = target_key_for_call(pretty, block.arguments)
            action_id = await _offload_blocking_io(
                ledger.record_start,
                agent=self.name,
                job_id=job.id,
                tool=pretty,
                args=block.arguments,
                target_key=tk,
            )
            self._inflight_actions[block.id] = action_id
            # Bound the in-flight dict — if a tool_use never gets a paired
            # result (SDK quirk, agent killed mid-call) we'd grow forever.
            # 256 is well above any realistic in-flight count.
            if len(self._inflight_actions) > 256:
                # Drop the oldest by insertion order (Python 3.7+ dicts
                # preserve insertion). The orphaned row stays in the DB
                # with outcome=NULL — visible as "in-flight" forever.
                drop_key = next(iter(self._inflight_actions))
                self._inflight_actions.pop(drop_key, None)
        except Exception:
            pass

    def _render_prior_actions_block(self, prompt: str) -> str:
        """Build a 'Prior actions in this engagement' block for the
        incoming task. Targets mentioned in the prompt (IPs, hosts,
        URLs) drive the query; if none are mentioned we fall back to
        the most-recent actions overall so the agent at least sees
        what's happening around it.

        Capped at ~15 lines so the block doesn't dominate the prompt.
        Returns an empty string when the ledger has nothing relevant —
        no need to inject noise into a clean engagement."""
        ledger = getattr(self, "_action_ledger", None)
        if ledger is None:
            return ""
        try:
            target_keys = extract_target_keys_from_text(prompt)
            if target_keys:
                rows = ledger.recent_for_targets(
                    target_keys,
                    per_target_limit=5,
                    overall_limit=15,
                )
                header_targets = ", ".join(target_keys[:4])
                if len(target_keys) > 4:
                    header_targets += f", +{len(target_keys) - 4} more"
                header = (
                    f"Prior actions in this engagement touching {header_targets} (newest first):"
                )
            else:
                rows = ledger.query(limit=10)
                header = "Recent actions in this engagement (newest first):"
            if not rows:
                return ""
            body = "\n".join(f"  {a.to_line()}" for a in rows)
            footer = (
                "If the same tool+target already ran here with a usable "
                "result, cite that outcome instead of re-running. Use "
                "prior_actions(target=…) for more."
            )
            return f"{header}\n{body}\n{footer}"
        except Exception:
            return ""

    async def _render_prior_actions_block_async(self, prompt: str) -> str:
        """Async episodic recall. When an embedder is configured, widen the
        candidate pool and RE-RANK by similarity to the task (blended 0.7 cosine
        + 0.3 recency) instead of pure recency. Falls back to the sync
        recency/target block — byte-identical to today — when there is no
        embedder, no daemon, or on any failure."""
        daemon = getattr(self, "_daemon", None)
        ledger = getattr(self, "_action_ledger", None)
        if ledger is None or daemon is None:
            return self._render_prior_actions_block(prompt)
        try:
            from ..memory.embeddings import cosine, get_embedder

            embedder = get_embedder(getattr(daemon, "profile", None))
        except Exception:
            embedder = None
        if embedder is None:
            return self._render_prior_actions_block(prompt)
        try:
            target_keys = extract_target_keys_from_text(prompt)
            if target_keys:
                rows = ledger.recent_for_targets(
                    target_keys,
                    per_target_limit=8,
                    overall_limit=30,
                )
                ht = ", ".join(target_keys[:4])
                if len(target_keys) > 4:
                    ht += f", +{len(target_keys) - 4} more"
                header = f"Prior actions in this engagement touching {ht} (most relevant first):"
            else:
                rows = ledger.query(limit=30)
                header = "Recent actions in this engagement (most relevant first):"
            if not rows:
                return ""
            if len(rows) > 15:
                qv = await embedder.embed_one(prompt[:2000])
                vecs = await embedder.embed([a.to_line() for a in rows])
                if qv and vecs and len(vecs) == len(rows):
                    n = len(rows)
                    scored = [
                        (
                            0.7 * cosine(qv, vecs[i])
                            + 0.3 * (1.0 - (i / (n - 1)) if n > 1 else 1.0),
                            a,
                        )
                        for i, a in enumerate(rows)
                    ]
                    scored.sort(key=lambda t: t[0], reverse=True)
                    rows = [a for _, a in scored[:15]]
                else:
                    rows = rows[:15]
            else:
                rows = rows[:15]
            body = "\n".join(f"  {a.to_line()}" for a in rows)
            footer = (
                "If the same tool+target already ran here with a usable "
                "result, cite that outcome instead of re-running. Use "
                "prior_actions(target=…) for more."
            )
            return f"{header}\n{body}\n{footer}"
        except Exception:
            return self._render_prior_actions_block(prompt)

    async def _render_relevant_memory_block(self, prompt: str) -> str:
        """Semantic recall: inject the KG facts most relevant (by embedding
        similarity) to the task. Empty when no embedder is configured, when the
        profile opts out (`embeddings.inject_recall: false`), or when nothing
        clears the score floor. Complements the agent-callable kg_semantic_query."""
        daemon = getattr(self, "_daemon", None)
        if daemon is None:
            return ""
        try:
            from ..memory.recall import semantic_recall

            profile = getattr(daemon, "profile", None)
            emb_block = (profile or {}).get("embeddings") or {}
            if emb_block.get("inject_recall") is False:
                return ""
            kg = getattr(daemon, "kg", None)
            if kg is None:
                return ""
            hits = await semantic_recall(kg, profile, prompt[:2000], top_k=6, min_score=0.6)
            if not hits:
                return ""
            body = "\n".join(f"  [{s:.2f}] {f}" for f, s in hits)
            return (
                "Relevant prior knowledge (semantic recall from the cross-engagement KG):\n" + body
            )
        except Exception:
            return ""

    def _render_skills_hint_block(self, prompt: str) -> str:
        """Surface skill-library playbooks relevant to the incoming task — names
        + one-line descriptions only, so the block stays cheap and the agent
        pulls the full methodology on demand with ``get_skill(<name>)``. Returns
        '' when nothing is relevant: a task the curated library doesn't cover
        gets no noise. Bodies are never injected, so a newly-approved skill shows
        up here with no agent reset (it reads ``daemon.skills`` live).

        Relevance is scored the probabilistic-retrieval way (BM25-style IDF)
        rather than raw token overlap: each curated tag token's weight is the
        log-odds that it's *informative*, learned from the library itself, so
        tokens shared by many skills carry ~0 weight while rare, specific ones
        ("changelog", "migration") dominate. IDF only knows CORPUS frequency, not
        general-English frequency, so a small stopword pre-filter
        (``_SKILL_HINT_STOPWORDS``) first strips function/framing words that are
        common in prose yet rare in the library ("for", "write") and would
        otherwise score as informative — the textbook stopword+IDF pairing; that
        list is load-bearing, not decorative (see the word-sense test). A skill
        must then share at least TWO DISCRIMINATING tokens (each unique to it or
        in ≤⅓ of the library) to surface — two independent specific cues is
        signal; one lone specific token is too often an ordinary word that
        merely coincides with a unique keyword ("rules" of engagement → a
        hashcat-rules playbook), so single-cue tasks deliberately get no hint.
        (The ⅓ ratio is corpus-relative; in a tiny library a token in >⅓ won't
        qualify even if relevant, but the unique-token escape keeps it
        discriminating at any size.) Recomputed per task (library is small and
        mutates live on skill approval), so there's no cache to invalidate."""
        daemon = getattr(self, "_daemon", None)
        skills = getattr(daemon, "skills", None) if daemon is not None else None
        if not skills:
            return ""
        try:
            import math as _math
            import re as _re

            def _toks(text: str) -> set[str]:
                return {w for w in _re.split(r"[^a-z0-9]+", str(text).lower()) if len(w) >= 3}

            # Strip general-English function/framing words IDF can't recognize
            # as common (see _SKILL_HINT_STOPWORDS) — this is the query-side
            # half of the standard stopword+IDF pipeline.
            task = _toks(prompt[:2000]) - _SKILL_HINT_STOPWORDS
            if not task:
                return ""
            # Curated tag-token set per skill (name + keywords + tools +
            # category) — the vocabulary we score the task against.
            tagsets = {
                # str() each field: an agent-proposed skill could carry a
                # non-string keyword/tool (e.g. an unquoted YAML number), and a
                # raw " ".join would TypeError → the blanket except would then
                # silently disable the hint for EVERY task, not just that skill.
                name: _toks(" ".join(str(x) for x in [s.name, s.category, *s.keywords, *s.tools]))
                for name, s in skills.items()
            }
            n = len(tagsets) or 1
            df: dict[str, int] = {}
            for tset in tagsets.values():
                for t in tset:
                    df[t] = df.get(t, 0) + 1

            # Smoothed BM25 IDF: rare tag token → high weight, ubiquitous → ~0.
            def _idf(t: str) -> float:
                d = df.get(t, 0)
                return _math.log(1.0 + (n - d + 0.5) / (d + 0.5))

            # A token discriminates if it's unique to one skill or sits in ≤⅓ of
            # the library. The ratio is corpus-relative: in a very small
            # library a token in >⅓ won't qualify even if relevant, while in a
            # large one the branch is permissive (a token shared by many
            # skills may still qualify — e.g. 27/81). d==1 is the precision
            # anchor at either end; the escape keeps a unique token
            # discriminating at any library size.
            def _discriminating(t: str) -> bool:
                d = df.get(t, 0)
                return d == 1 or (0 < d and d / n <= 0.34)

            scored = []
            for name, tset in tagsets.items():
                hit = task & tset
                # Require ≥2 discriminating tokens. One lone specific token is
                # too often an ordinary word that merely coincides with a unique
                # keyword — "rules" of engagement → a hashcat-rules playbook,
                # "open" ports → an OAuth open-redirect playbook. Two independent
                # specific cues is signal; one is noise. (Cost: a task whose only
                # cue is a single keyword gets no hint — rare, and the agent can
                # still search_skills.)
                if sum(1 for t in hit if _discriminating(t)) < 2:
                    continue
                scored.append((sum(_idf(t) for t in hit), skills[name]))
            if not scored:
                return ""
            scored.sort(key=lambda t: (-t[0], t[1].name))
            hits = [s for _, s in scored[:3]]
            body = "\n".join(f"  {s.name} — {s.description}" for s in hits)
            return (
                "Skill-library playbooks that may fit this task — load one with "
                "get_skill(<name>) before reinventing its methodology:\n" + body
            )
        except Exception:
            _log.debug("skills hint render failed", exc_info=True)
            return ""

    def _provider_label(self) -> str:
        """Best-effort provider name for a block event's `meta.block`.

        Derived from the agent's `endpoint:` override base_url so the
        operator-console blocks indicator can show "MiniMax · rate_limit"
        without inferring the provider from the agent name. Agents with no
        endpoint override run on the daemon's native host → 'anthropic';
        local inference (LM Studio / Ollama / LiteLLM) → 'local'."""
        ep = (self.cfg or {}).get("endpoint") or {}
        base = (ep.get("base_url") or "").lower()
        if not base:
            return "anthropic"
        if "minimax" in base:
            return "minimax"
        if "deepseek" in base:
            return "deepseek"
        if "anthropic.com" in base:
            return "anthropic"
        return "local"

    async def _maybe_log_refusal(
        self,
        job: "Job",
        msg: AssistantEvent,
    ) -> None:
        """Detect Anthropic-side refusals AND SDK/transport errors on
        an assistant message and emit a structured `refusal` event
        with surrounding context for triage.

        Two distinct categories, surfaced with different log labels
        but funneled into the same JSONL event type so a single
        `logs grep refusal` finds both:

          REFUSAL — policy/content-driven, the model declined:
            • stop_reason == 'refusal' (explicit content-policy stop)
            • text markers in real model output ("API Error:",
              "violate our Usage Policy", etc.) — fallback for older
              SDKs that don't populate stop_reason.

          ERROR — SDK / transport / billing / quota failures, no
          model output:
            • msg.error is set (authentication_failed, billing_error,
              rate_limit, invalid_request, server_error, unknown).
              The SDK manufactures a synthetic AssistantMessage with
              model='<synthetic>' to surface these.

        `stop_reason='stop_sequence'` is NOT a trigger — it's normal
        model behavior (hitting a configured stop string), and the
        SDK also sets it on synthetic error envelopes (where the real
        signal is msg.error).

        Event payload includes agent, job id + prompt, model, the
        assistant text (capped), and the last 5 ledger rows so the
        operator can see what tool calls preceded the event —
        usually the trigger is in the immediately-prior tool result
        the model was reacting to."""
        if msg is None:
            return

        err = msg.error_code
        stop = msg.stop_reason

        text_content_parts: list[str] = []
        for block in msg.content or []:
            if isinstance(block, TextContent):
                text_content_parts.append(block.text)
        text_content = "\n".join(text_content_parts).strip()

        is_refusal = False
        is_error = False
        reason_parts: list[str] = []

        if stop == "refusal":
            is_refusal = True
            reason_parts.append("stop_reason=refusal")

        if text_content:
            markers = (
                "API Error:",
                "unable to respond to this request",
                "violate our Usage Policy",
                "Usage Policy",
            )
            if any(m in text_content for m in markers):
                is_refusal = True
                reason_parts.append("text_marker")

        auth_recover = False
        if err:
            is_error = True
            reason_parts.append(f"sdk_error={err}")
            if err in _AUTH_RECOVER_ERRORS:
                # OAuth token rotated out from under this subprocess. Signal
                # _dispatch_job to reconnect + retry once, rather than letting
                # the agent 401 on every subsequent turn until an operator reset.
                auth_recover = True
                self._auth_recover_pending = True

        if not (is_refusal or is_error):
            return

        recent_tools: list[str] = []
        try:
            ledger = getattr(self, "_action_ledger", None)
            if ledger is not None:
                rows = ledger.query(limit=5)
                recent_tools = [a.to_line() for a in rows]
        except Exception:  # noqa: BLE001
            pass

        kind = "refusal" if is_refusal else "error"
        self.total_refusals += 1
        payload = {
            "agent": self.name,
            "job_id": getattr(job, "id", None),
            "job_prompt": (getattr(job, "prompt", "") or "")[:600],
            "model": getattr(msg, "model", None),
            "stop_reason": stop,
            "sdk_error": err,
            "kind": kind,
            "reason": ",".join(reason_parts) or "unknown",
            "text": text_content[:2000],
            "recent_tool_calls": recent_tools,
        }
        await self._record_jsonl("refusal", payload)
        label = "MODEL REFUSAL" if is_refusal else "MODEL ERROR"
        hint = (
            " — credential may have rotated; reconnecting SDK client and "
            "retrying once (else run `reset <agent>`)"
            if auth_recover
            else ""
        )
        # Ride the structured block payload on the live event's `meta` so the
        # operator-console "blocks" indicator can render agent · provider ·
        # reason without re-parsing the display text. Purely additive — every
        # existing consumer ignores unknown `meta` keys.
        block_meta = {
            "block": {
                "category": kind,  # "refusal" vs "error"
                "provider": self._provider_label(),
                "model": payload["model"],
                "error_code": payload["sdk_error"],  # e.g. "rate_limit"
                "stop_reason": payload["stop_reason"],
                "reason": payload["reason"],  # short triage summary
            }
        }
        await self._log(
            "refusal",
            f"⚠ {label} ({payload['reason']}) — model="
            f"{payload['model']!r} — see logs/<agent>.jsonl 'refusal' "
            f"for full context (prompt + recent tools + text){hint}",
            meta=block_meta,
        )

    async def _action_ledger_finish(
        self,
        block: ToolResultEvent,
        text: str,
        *,
        is_error: bool,
    ) -> None:
        """Fill in outcome+summary on the row started by _action_ledger_start.
        Summary is the first non-empty line of the tool result, capped. The
        in-memory pop stays on the loop; the SQLite write is offloaded."""
        ledger = getattr(self, "_action_ledger", None)
        if ledger is None:
            return
        action_id = self._inflight_actions.pop(block.tool_call_id, None)
        if action_id is None:
            return
        try:
            outcome = "error" if is_error else "ok"
            first_line = ""
            for line in (text or "").splitlines():
                stripped = line.strip()
                if stripped:
                    first_line = stripped
                    break
            await _offload_blocking_io(
                ledger.record_finish,
                action_id,
                outcome=outcome,
                summary=first_line,
            )
        except Exception:
            pass

    def _log_jsonl(
        self,
        kind: str,
        content: Any,
        *,
        source: str | None = None,
        recipient: str | None = None,
    ) -> None:
        """Append a structured event to <engagement>/logs/<agent>.jsonl
        AND mirror it to the events table in the bus DB (for SQL
        aggregations: tool-call counts, error patterns, delegation
        graphs). JSONL is grep-friendly; the events table is queryable.

        Both sinks are best-effort. JSONL is no-op when no engagement
        path is set; events table is no-op when no DB is configured.

        `source` / `recipient` are populated for inter-actor message
        events (user_message / peer_message / operator_answer); they
        let an operator-facing transcript reconstruct who-said-what
        without grepping prose. Both fields are written to JSONL when
        non-None and threaded to record_event for SQL indexing."""
        ts = time.time()
        # Redact secret-valued tool-call arg fields before EITHER sink — the
        # JSONL file below AND the mirrored events table both receive `content`.
        # Structural / field-name only (result text is left intact and protected
        # by the 0600 file mode). Idempotent if the caller already redacted.
        if isinstance(content, dict):
            _tn = content.get("tool") or content.get("tool_pretty")
            content = _redact_secret_fields(
                content,
                tool=_tn if isinstance(_tn, str) else None,
            )
        eng = getattr(self, "_engagement_path", None)
        if eng is not None:
            try:
                if self._jsonl_fh is None:
                    log_dir = eng / "logs"
                    log_dir.mkdir(parents=True, exist_ok=True)
                    _jsonl_path = log_dir / f"{self.name}.jsonl"
                    self._jsonl_fh = _jsonl_path.open("a")
                    # Logs carry tool I/O (incl. result text with creds) — keep
                    # them owner-only; dir 0700 also shields any sibling files.
                    os.chmod(log_dir, 0o700)
                    os.chmod(_jsonl_path, 0o600)
                rec: dict[str, Any] = {
                    "ts": ts,
                    "agent": self.name,
                    "kind": kind,
                    "content": content,
                }
                if source is not None:
                    rec["source"] = source
                if recipient is not None:
                    rec["recipient"] = recipient
                self._jsonl_fh.write(json.dumps(rec, default=str) + "\n")
                self._jsonl_fh.flush()
            except OSError as e:
                # Disk-full / permissions — drop rather than crash the agent
                # over a logging failure, but warn once so it isn't invisible.
                self._warn_log_failure("jsonl", e)
        if self.context is not None:
            tool: str | None = None
            job_id: int | None = None
            if isinstance(content, dict):
                # Pull out the indexable bits so SQL queries on
                # (kind, tool, job_id) are fast.
                tn = content.get("tool") or content.get("tool_pretty")
                if isinstance(tn, str):
                    tool = tn
                jid = content.get("job_id")
                if isinstance(jid, int):
                    job_id = jid
            self.context.record_event(
                agent=self.name,
                kind=kind,
                content=content,
                tool=tool,
                job_id=job_id,
                ts=ts,
                source=source,
                recipient=recipient,
            )

    # ── off-loop persistence wrappers ────────────────────────────────────
    # The blocking sinks above (JSONL fsync + SQLite execute/commit) run on
    # pool threads via these wrappers so per-event/-tool/-job persistence can't
    # stall the agent event loop (which starved turns and tripped the web
    # keepalive — see the keepalive-ping-timeout fix). Safe because all stores
    # serialize every connection/cache access under their own RLock, so a
    # thread write never races an on-loop read. ALWAYS `await` these — never
    # `gather`/`create_task` — so only one offloaded write per runner is in
    # flight at a time (a runner is a single `_run` task), which keeps the
    # lazy `_jsonl_fh` open and `_inflight_actions` race-free.
    async def _record_jsonl(
        self,
        kind: str,
        content: Any,
        *,
        source: str | None = None,
        recipient: str | None = None,
    ) -> None:
        await _offload_blocking_io(
            self._log_jsonl,
            kind,
            content,
            source=source,
            recipient=recipient,
        )

    async def _record_evidence(self, job: "Job", kind: str, text: str) -> None:
        await _offload_blocking_io(self._save_evidence, job, kind, text)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"agent:{self.name}")

    def _bus_tool_meta(
        self,
        tool_name: str,
        tool_input: dict | None,
    ) -> dict | None:
        """Extract a structured meta dict for known bus tool calls so
        the web pane can render a rich card (source-chip → function-
        badge → target-chip + collapsible prompt body) instead of a
        dense monospace one-liner. Returns None for tools we don't
        special-case — caller falls back to the standard text rendering.

        Source name is the runner's canonical `self.name`, not parsed
        from the wire alias in `tool_name` (raw agent names get
        aliased before SDK registration; the runner already holds the
        real name, no reverse-alias needed)."""
        if not tool_name or not tool_name.startswith("mcp__bus__"):
            return None
        rest = tool_name[len("mcp__bus__") :]
        if "__" not in rest:
            return None
        # mcp__bus__<wire-owner>__<func>
        _wire_owner, func = rest.rsplit("__", 1)
        inp = tool_input or {}
        if func == "ask_agent":
            return {
                "subkind": "bus_ask_agent",
                "source": self.name,
                "target": inp.get("name"),
                "prompt": inp.get("prompt"),
                "max_turns": inp.get("max_turns"),
                "deliverable": inp.get("deliverable"),
                "prefer_primary": bool(inp.get("prefer_primary")),
            }
        if func == "ask_partner":
            return {
                "subkind": "bus_ask_partner",
                "source": self.name,
                "target": inp.get("name"),
                "prompt": inp.get("prompt"),
                "max_turns": inp.get("max_turns"),
                "deliverable": inp.get("deliverable"),
            }
        if func == "ask_operator":
            return {
                "subkind": "bus_ask_operator",
                "source": self.name,
                "target": "operator",
                "question": inp.get("question"),
            }
        if func == "context_write":
            return {
                "subkind": "bus_context_write",
                "source": self.name,
                "key": inp.get("key"),
                "value": inp.get("value"),
            }
        return None

    async def _idle_watchdog(
        self,
        process_task: asyncio.Task,
        *,
        idle_limit: float,
        check_interval: float = 30.0,
    ) -> float | None:
        """Background watchdog that cancels `process_task` if the
        runner stays idle longer than `idle_limit` seconds. Returns
        the actual idle duration on cancel, None on natural completion.

        IDLE definition:
          - no `_publish` event in the last `idle_limit` seconds
          - AND no tool currently in flight (`_inflight_actions` empty)

        The tool-in-flight skip is what makes this an *idle* timeout
        instead of a *total-runtime* one. Long-running tools (full
        sweeps, batch jobs, heavy analysis) don't eat the budget — only quiet
        stretches with no tools running do. Diagnosis lives in
        docs/COMM_PATHS.md section B failure-mode #3 followup.

        `check_interval` defaults to 30s for production; tests pass a
        smaller value so they don't sleep for half a minute. Capped
        at idle_limit/4 in `_run` so the watchdog can fire reasonably
        promptly for short idle limits."""
        while not process_task.done():
            try:
                await asyncio.sleep(check_interval)
            except asyncio.CancelledError:
                return None
            if process_task.done():
                return None
            if self._inflight_actions:
                # Tool in flight — not idle, even though _publish has
                # been quiet for the duration of the tool execution.
                continue
            idle = time.time() - self._last_activity_ts
            if idle > idle_limit:
                process_task.cancel()
                return idle
        return None

    async def _reconnect_client(self) -> None:
        """Tear down the current SDK client and spawn a fresh one. A new
        ClaudeSDKClient subprocess re-reads ~/.claude/.credentials.json, so it
        picks up an OAuth token rotated out from under the long-lived subprocess
        (the authentication_failed recovery path). Drops the agent's in-process
        conversation history — same as `reset` — which is acceptable here: the
        auth-failed turn produced no usable output and the job is re-run."""
        with suppress(Exception):
            if self._backend is not None:
                await self._backend.disconnect()
        self._backend = self._create_backend()
        await self._backend.connect()

    async def _run_job(self, job: "Job") -> None:
        """Process one job: launch the receive-response task under an idle
        watchdog and translate cancellation / SDK errors onto job.error.
        Extracted from _run so _dispatch_job's auth-recovery retry can re-invoke
        it on a freshly reconnected client, and so the watchdog + error mapping
        are unit-testable in isolation."""
        # Idle-watchdog dispatch: `prompt_timeout` is the MAX
        # IDLE WINDOW, not total runtime. While the agent is
        # publishing events (text, tool-call, tool-result) the
        # idle clock is reset by _publish. While a tool is in
        # flight (_inflight_actions non-empty) the watchdog
        # skips the idle check entirely — so a 25-min
        # long-running call doesn't burn the agent's wait budget. The
        # previous semantics (total-runtime wait_for) burned
        # an hour on node-01 when the agent was actually
        # making progress through a series of long jobs.
        self._last_activity_ts = time.time()
        watchdog: asyncio.Task | None = None
        self._turn_active = True  # a turn is now streaming
        proc_task = asyncio.create_task(
            self._process(job),
            name=f"process:{self.name}:{job.id}",
        )
        if self.prompt_timeout and self.prompt_timeout > 0:
            check_interval = min(30.0, max(1.0, self.prompt_timeout / 4))
            watchdog = asyncio.create_task(
                self._idle_watchdog(
                    proc_task,
                    idle_limit=self.prompt_timeout,
                    check_interval=check_interval,
                ),
                name=f"watchdog:{self.name}:{job.id}",
            )
        try:
            await proc_task
        except asyncio.CancelledError:
            # Attribute the cancellation to its INITIATOR before reclassifying.
            # The idle watchdog cancels `proc_task`, so the CancelledError
            # arrives THROUGH `await proc_task` while our own task's
            # `cancelling()` stays 0. An external stop cancels the runner's
            # OWNING task (`cancelling() > 0`) or trips `_stop_requested`.
            # Blindly attributing every CancelledError to the watchdog turned an
            # external stop into a false "idle timeout" and left the runner
            # alive; only a genuine watchdog cancel may be reclassified as an
            # idle timeout — anything else must re-raise so the cancellation
            # actually unwinds the runner.
            current = asyncio.current_task()
            externally_cancelled = self._stop_requested or (
                current is not None and current.cancelling() > 0
            )
            # Non-awaiting check: the watchdog's `return idle` completes its task
            # in the same loop step as `proc_task.cancel()`, strictly before we
            # resume here — so `.result()` is available without an `await` that
            # would itself re-raise under external cancellation.
            watchdog_fired = (
                watchdog is not None
                and watchdog.done()
                and not watchdog.cancelled()
                and watchdog.exception() is None
                and watchdog.result() is not None
            )
            if externally_cancelled or not watchdog_fired:
                # External stop wins over idle attribution (a hung stop is worse
                # than a mislabeled job error); an unattributed cancel we refuse
                # to guess about is likewise treated as external. Record a
                # terminal reason and re-raise so the runner's task unwinds
                # instead of returning to idle.
                job.error = "runner stopping"
                raise
            idle_secs = watchdog.result() or self.prompt_timeout  # type: ignore[union-attr]
            job.error = f"idle timeout after {idle_secs:.0f}s of inactivity"
            self._last_interrupt_reason = (
                f"RUNNER IDLE TIMEOUT after {idle_secs:.0f}s "
                f"— no agent events for the configured idle "
                f"window, and no tool was in flight. Operator "
                f"did NOT reject; the runner interrupted to "
                f"keep the dispatch chain moving."
            )
            with suppress(Exception):
                if self._backend is not None:
                    await self._backend.interrupt()
            await self._log("tool-error", job.error)
        except Exception as e:
            # Three-way classification: SDK-recognized death,
            # returncode-probed death (text didn't match but
            # the kernel says the proc exited), or a genuine
            # SDK internal error. See classify_run_loop_error
            # for the full layering — extracted so the logic
            # is unit-testable without standing up the SDK.
            job.error = (
                self._backend.diagnose_failure(self.name, e, tuple(self.stderr_buffer))
                if self._backend is not None
                else classify_run_loop_error(
                    self.name,
                    e,
                    None,
                    stderr_tail=self.stderr_buffer,
                )
            )
            await self._log("tool-error", job.error)
        finally:
            # Turn is no longer streaming — a steer from here on
            # (finalization window: get_context_usage, on_job_complete)
            # must NOT fire an interrupt.
            self._turn_active = False
            if watchdog is not None and not watchdog.done():
                watchdog.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await watchdog

    async def _dispatch_job(self, job: "Job") -> None:
        """Run one job with bounded auto-recovery from an OAuth-rotation 401.
        On sdk_error=authentication_failed (_maybe_log_refusal sets
        _auth_recover_pending) the subprocess is holding a token rotated out
        from under it; reconnect (a fresh subprocess re-reads the credential)
        and re-run the job once. Capped at _MAX_AUTH_RECOVERIES so a genuinely
        bad credential surfaces the refusal instead of looping forever."""
        auth_attempts = 0
        while True:
            self._auth_recover_pending = False
            await self._run_job(job)
            if (
                self._auth_recover_pending
                and auth_attempts < _MAX_AUTH_RECOVERIES
                and not self._stop_requested
            ):
                auth_attempts += 1
                await self._log(
                    "system",
                    f"auth recovery {auth_attempts}/{_MAX_AUTH_RECOVERIES}: "
                    "reconnecting SDK client after suspected OAuth token "
                    "rotation (sdk_error=authentication_failed)",
                )
                await asyncio.sleep(_AUTH_RECOVER_BACKOFF)
                try:
                    await self._reconnect_client()
                except Exception as e:  # noqa: BLE001
                    await self._log(
                        "tool-error",
                        f"auth recovery reconnect failed: {e}",
                    )
                    return
                continue
            return

    async def _connect_with_attach_retry(self) -> None:
        """Connect the backend, with a bounded retry dedicated to codex
        bus-gateway attach failures (own budget, separate from auth-401
        recovery). The gateway race is fixed upstream, so an attach failure here
        means a genuinely broken gateway/codex; retry a couple times with
        backoff (fresh credential each time), then FAULT loudly — a delegation
        agent that silently lacks ask_agent is worse than one that visibly failed
        to start."""
        attempt = 0
        while True:
            assert self._backend is not None
            try:
                await self._backend.connect()
                return
            except GatewayAttachError as err:
                if attempt >= _MAX_GATEWAY_ATTACH_RETRIES:
                    self.status = "faulted"
                    _log.error("agent %s FAULTED (codex bus): %s", self.name, err)
                    with suppress(Exception):
                        await self._log(
                            "tool-error",
                            f"codex bus gateway attach failed after "
                            f"{attempt + 1} attempts ({err.rung}); agent NOT "
                            f"started — it would have no ask_agent/bus tools.",
                        )
                    raise
                backoff = _GATEWAY_ATTACH_BACKOFF[min(attempt, len(_GATEWAY_ATTACH_BACKOFF) - 1)]
                attempt += 1
                with suppress(Exception):
                    await self._log(
                        "system",
                        f"codex bus gateway attach retry "
                        f"{attempt}/{_MAX_GATEWAY_ATTACH_RETRIES} in {backoff}s ({err.rung})",
                    )
                await asyncio.sleep(backoff)
                self._backend = self._create_backend()  # fresh credential for the retry

    async def _hard_refuse_operator_prompt(self, job: Job) -> bool:
        daemon_profile = getattr(self._daemon, "profile", None)
        try:
            config = resolve_config(self.cfg, daemon_profile)
        except OperatorPromptModeError as error:
            job.error = f"invalid safeguard configuration: {error}"
            meta = {
                "agent": self.name,
                "job_id": job.id,
                "reason": "invalid_operator_prompt_mode",
            }
            self._publish(
                "safeguard_prompt_config_error", "invalid safeguard configuration", meta=meta
            )
            await self._record_jsonl("safeguard_prompt_config_error", meta)
            return True
        self._safeguard_config = config
        match config.operator_prompt_mode:
            case OperatorPromptMode.HARD_REFUSE:
                pass
            case OperatorPromptMode.LOG | OperatorPromptMode.SOFT_REFUSE:
                return False
            case unreachable:
                assert_never(unreachable)
        if self.total_prompt_hard_blocks >= config.halt_threshold:
            job.error = (
                f"runner halted after {self.total_prompt_hard_blocks}/"
                f"{config.halt_threshold} safeguard blocks; reset required"
            )
            meta = {
                "agent": self.name,
                "job_id": job.id,
                "reason": "halt_threshold_reached",
                "mode": config.operator_prompt_mode.value,
                "count": self.total_prompt_hard_blocks,
                "halt_at": config.halt_threshold,
            }
            self._publish("safeguard_prompt_halt", "runner halted by safeguards", meta=meta)
            await self._record_jsonl("safeguard_prompt_halt", meta)
            return True
        allowed, reason = check_prompt_intent(
            job.prompt,
            config=config,
            dataset=self._policy_dataset,
        )
        if allowed:
            return False
        self.total_safeguard_blocks += 1
        self.total_prompt_hard_blocks += 1
        job.error = f"operator prompt blocked by safeguard: {reason}"
        meta = {
            "agent": self.name,
            "job_id": job.id,
            "reason": reason,
            "mode": OperatorPromptMode.HARD_REFUSE.value,
            "count": self.total_prompt_hard_blocks,
            "halt_at": config.halt_threshold,
        }
        self._publish("safeguard_prompt_block", "operator prompt blocked", meta=meta)
        await self._record_jsonl("safeguard_prompt_block", meta)
        return True

    async def _run(self) -> None:
        try:
            self._backend = self._create_backend()
            await self._connect_with_attach_retry()
            self.status = "idle"
            await self._log("start", "ready")
            while not self._stop_requested:
                # Priority lane FIRST: an operator steer jumps ahead of any
                # FIFO-queued prompts and runs at this (next) turn boundary.
                steer = self._steer_lane.popleft() if self._steer_lane else None
                if steer is not None:
                    job = steer
                else:
                    try:
                        timeout = self.idle_timeout if self.idle_timeout > 0 else None
                        job = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                    except TimeoutError:
                        await self._log("done", f"idle timeout ({self.idle_timeout}s)")
                        break
                    if job is None:  # shutdown sentinel
                        break
                    if job is _STEER_WAKE:  # steer woke us — drain the lane
                        continue
                self.current = job
                self.status = "busy"
                job.started_at = time.time()
                # Per-turn processing + bounded auto-recovery from an
                # OAuth-rotation 401 (see _dispatch_job / _run_job).
                if not await self._hard_refuse_operator_prompt(job):
                    await self._dispatch_job(job)
                job.finished_at = time.time()
                self.last_active = job.finished_at
                self._record_job_history(job)
                # Refresh authoritative context-usage snapshot from the SDK.
                # Best-effort — older SDKs may not have this, and any RPC
                # error here shouldn't fail the job. Also gives the operator
                # accurate context-percentage for `status` / `usage` views.
                if self._backend is not None:
                    try:
                        usage = await self._backend.get_context_usage()
                        self.last_context_usage = (
                            {
                                "totalTokens": usage.used_tokens,
                                "maxTokens": usage.max_tokens,
                                "percentage": usage.percentage,
                                "model": usage.model,
                            }
                            if usage is not None
                            else None
                        )
                    except Exception:
                        pass
                # Run completion hook BEFORE the context-bus write so it can
                # extract <ask_operator> markers and strip them from job.result.
                if self.on_job_complete is not None:
                    try:
                        self.on_job_complete(self, job)
                    except Exception as e:
                        await self._log("tool-error", f"on_job_complete error: {e}")
                if self.context is not None and job.error is None and job.result:
                    # Single sliding-window write. We previously also wrote
                    # to <agent>/job_<id> but nothing ever read those keys
                    # (no context_read consumer references them) — the
                    # extra UPSERT was pure SQLite waste.
                    await _offload_blocking_io(
                        self.context.write,
                        self.name,
                        "latest",
                        job.result,
                    )
                # Persist the job row regardless of success/failure so the
                # operator's `info <agent>` view (and any future audit)
                # survives a daemon restart.
                if self.context is not None:
                    await _offload_blocking_io(
                        self.context.record_job,
                        agent=self.name,
                        job_id=job.id,
                        prompt=job.prompt,
                        submitted_at=job.submitted_at,
                        started_at=job.started_at,
                        finished_at=job.finished_at,
                        result=job.result,
                        error=job.error,
                        prompt_sha=getattr(self, "_prompt_sha", None),
                    )
                if job.future and not job.future.done():
                    job.future.set_result(job)
                self.current = None
                self.status = "idle"
        finally:
            # Resolve any pending futures (current job mid-flight + queued
            # jobs) so callers' ask_agent awaits unblock instead of leaking.
            # Without this, when an agent dies (kill, crash, queue sentinel)
            # any caller blocked on `await fut` inside bus.ask_agent waits
            # for runner.prompt_timeout — usually 1230s of mystery.
            self._fail_pending_futures(reason="agent stopped before reply")
            with suppress(Exception):
                if self._backend:
                    await self._backend.disconnect()
            self.status = "stopped"
            await self._log("done", "stopped")
            if self._jsonl_fh is not None:
                with suppress(Exception):
                    self._jsonl_fh.close()
                self._jsonl_fh = None

    def _fail_pending_futures(self, reason: str) -> None:
        """Set RuntimeError on every pending Job.future this runner owns."""
        # Currently-processing job
        if self.current is not None and self.current.future is not None:
            fut = self.current.future
            if not fut.done():
                fut.set_exception(RuntimeError(f"{self.name}: {reason}"))
        # Anything queued but never picked up
        try:
            while True:
                pending = self.queue.get_nowait()
                # Skip the control sentinels — neither carries a `.future`.
                # Missing _STEER_WAKE here would AttributeError and abort the
                # drain, leaking the futures of any real jobs queued behind it
                # (the same strand this teardown path exists to prevent).
                if pending is None or pending is _STEER_WAKE:
                    continue
                if pending.future is not None and not pending.future.done():
                    pending.future.set_exception(RuntimeError(f"{self.name}: {reason}"))
        except asyncio.QueueEmpty:
            pass

    async def _process(self, job: Job) -> None:
        assert self._backend is not None
        # Fresh per turn so a reason set by one job (steer / hard-cap / idle)
        # can never leak its attribution into a LATER job's synthetic block.
        self._last_interrupt_reason = None
        prompt = job.prompt
        orig = prompt  # memory blocks rank against the raw task, not each other
        skills_block = self._render_skills_hint_block(orig)
        if skills_block:
            prompt = f"{skills_block}\n\n---\n\n{prompt}"
        prior_block = await self._render_prior_actions_block_async(orig)
        if prior_block:
            prompt = f"{prior_block}\n\n---\n\n{prompt}"
        recall_block = await self._render_relevant_memory_block(orig)
        if recall_block:
            prompt = f"{recall_block}\n\n---\n\n{prompt}"
        if self._scope_store is not None:
            from ..policy.scope import render_scope_block

            scope_block = render_scope_block(self._scope_store)
            if scope_block:
                prompt = f"{scope_block}\n\n---\n\n{prompt}"
        # Always-on alias layer: rewrite raw agent names → neutral
        # descriptive labels (e.g. auth-probe, module-runner) before
        # sending to the model. Disable for a
        # specific run with SALIENT_ALIAS_NAMES=0.
        from ..alias import rewrite_outbound as _alias_outbound

        prompt = _alias_outbound(prompt)
        await self._backend.query(prompt)
        chunks: list[str] = []
        # Wire-level enforcement of the per-dispatch turn budget. The
        # delegation envelope's "HARD CEILING of N turns" is prose the
        # model can ignore; without this, shadows have been observed
        # running to the SDK's internal ~31-turn cap and dangling caller
        # futures until the 1200s prompt-timeout.
        #
        # Buffer = 12: this counter increments on every AssistantMessage
        # but the SDK's authoritative `num_turns` (reported in
        # ResultMessage) doesn't count retry / recovery model invocations
        # — tool-permission refusals, SDK-internal re-prompts, etc. add
        # to our counter but not to num_turns. A buffer of 12 absorbs
        # those retries for typical multi-variant work (multi-stage
        # tool chains) while still catching a true runaway well before the
        # SDK's ~31-turn internal ceiling. The previous buffer of 2 was
        # too tight: budget=12 capped at 14 by our counter while the SDK
        # only counted 11 actual turns at that point, so the agent was
        # still mid-deliverable when we cut it off.
        # Per-agent override (defaults to 12). Complex multi-stage
        # utilities and their shadows run multi-stage chains
        # (enumerate → act → advance → collect → persist) that need
        # more retry/recovery slack than single-shot agents; set to 24 in
        # their cfg. Single-shot agents stay at 12.
        _HARD_CAP_BUFFER = int((self.cfg or {}).get("hard_cap_buffer", 12))
        # Per-dispatch budget hint wins; otherwise fall back to the agent's
        # static cfg max_turns so backends with no native turn enforcement
        # (codex — ClaudeAgentOptions.max_turns never reaches them) still get
        # this runner-level backstop. Claude-path backends stop at cfg
        # max_turns inside the SDK first, so the fallback only ever fires for
        # backends that don't self-enforce.
        turn_cap: int | None = job.max_turns_hint or (self.cfg or {}).get("max_turns")
        # Reset the runner-exposed counter at job start so the budget-
        # chip hook reads 0 → N progression cleanly per dispatch. The
        # local `turn_count` alias keeps the rest of the function
        # readable; we update both in lockstep.
        self.current_turn_count = 0
        turn_count = 0
        cap_fired = False
        # Silent-completion nudge counters. The receive-response loop is
        # wrapped in a `while True` below so we can re-query the SDK
        # ONCE with a nudge prompt when an agent ends with no tool calls
        # AND no <ask_operator> marker AND a caller is awaiting on this
        # job. The pattern caught: agent receives an ask_agent delegation,
        # decides it's "done" without doing anything, returns empty reply,
        # caller's future resolves with nothing, and the whole tree falls
        # silent because nobody asked the operator what to do. Capped at
        # 1 per job to prevent thrash. Diagnosis: docs/COMM_PATHS.md
        # section B failure-mode #2.
        tool_uses_in_job = 0
        nudge_fired = False
        while True:
            chunks_before = len(chunks)
            tools_before = tool_uses_in_job
            async for msg in self._backend.receive_response():
                if isinstance(msg, AssistantEvent):
                    turn_count += 1
                    self.current_turn_count = turn_count
                    for block in msg.content:
                        if isinstance(block, TextContent):
                            chunks.append(block.text)
                            await self._log("text", block.text)
                        elif isinstance(block, ThinkingContent):
                            if block.text.strip():
                                await self._log_truncated("thinking", block.text, 800)
                        elif isinstance(block, ToolCallContent):
                            tool_uses_in_job += 1
                            # Redact secret arg VALUES (password / api_token / …)
                            # up front so neither the live operator feed, the
                            # rich web card, nor the persisted JSONL/events row
                            # shows a captured credential. `block.input` itself
                            # stays intact for _check_loop + the action ledger,
                            # which need the real args (loop dedup +
                            # prior_actions retry).
                            safe_input = _redact_secret_fields(
                                block.arguments,
                                tool=block.name,
                            )
                            args = _format_tool_args(safe_input)
                            pretty = _prettify_tool_name(block.name)
                            label = f"{pretty}  {args}" if args else pretty
                            # Build a structured meta dict for known
                            # bus tool calls so the web pane can render
                            # a rich card; the text label is still the
                            # CLI / fallback rendering.
                            bus_meta = self._bus_tool_meta(
                                block.name,
                                safe_input,
                            )
                            # Structured tool identity for stream consumers
                            # (the TUI REPL pairs tool-call→tool-result by id
                            # and renders the real tool name/input). Additive
                            # to bus_meta; the web pane ignores unknown keys.
                            call_meta: dict[str, Any] = {
                                "tool_call": {
                                    "id": block.id,
                                    "name": pretty,
                                    "input": safe_input,
                                },
                            }
                            if bus_meta:
                                call_meta = {**bus_meta, **call_meta}
                            await self._log_truncated(
                                "tool-call",
                                label,
                                400,
                                meta=call_meta,
                            )
                            # JSONL gets the FULL (redacted) input dict, not the
                            # truncated display label — so `logs grep` can still
                            # match any non-secret arg value (channel=0, …).
                            await self._record_jsonl(
                                "tool-call",
                                {
                                    "tool": block.name,
                                    "tool_pretty": pretty,
                                    "input": safe_input,
                                    "label": label,
                                    "job_id": job.id,
                                },
                            )
                            # Use the prettified name (mcp__server__tool stripped
                            # to bare tool name) so the counter aggregates by
                            # what the operator sees in the log/info view.
                            self.tool_call_counts[pretty] += 1
                            await self._check_loop(
                                block.name,
                                block.arguments,
                                tool_use_id=block.id,
                            )
                            await self._action_ledger_start(job, block, pretty)
                        else:
                            assert_never(block)
                    # After all blocks are processed, check whether THIS
                    # assistant message is a Usage-Policy / API-error refusal
                    # and emit a structured `refusal` event if so.
                    await self._maybe_log_refusal(job, msg)
                    # Wire-level cap: if this dispatch carries a budget hint
                    # and we've crossed it (plus the small tool-echo buffer),
                    # interrupt the SDK and synthesize a PARTIAL completion
                    # note so the caller's BusCall future resolves promptly
                    # rather than dangling until the prompt_timeout deadline.
                    if turn_cap and not cap_fired and turn_count > turn_cap + _HARD_CAP_BUFFER:
                        cap_fired = True
                        cap_note = (
                            f"\n\n[PARTIAL: runner hard cap at turn "
                            f"{turn_count} (budget was {turn_cap} "
                            f"+ buffer {_HARD_CAP_BUFFER}). Agent did not "
                            f"deliver before exhausting its turn budget. "
                            f"Consider re-dispatching with a larger budget "
                            f"or splitting the task into smaller steps.]"
                        )
                        chunks.append(cap_note)
                        await self._log("hard-cap", cap_note.strip())
                        self._last_interrupt_reason = (
                            f"RUNNER HARD-CAP at turn {turn_count} "
                            f"(budget {turn_cap} + buffer "
                            f"{_HARD_CAP_BUFFER}). Operator did NOT "
                            f"reject; the runner cut the dispatch to "
                            f"keep the caller's future from dangling."
                        )
                        with suppress(Exception):
                            if self._backend is not None:
                                await self._backend.interrupt()
                        break
                elif isinstance(msg, ToolResultEvent):
                    text = _format_tool_result(msg.content)
                    if (
                        msg.is_error
                        and self._last_interrupt_reason is not None
                        and "doesn't want to proceed" in text
                    ):
                        text = (
                            f"[{self._last_interrupt_reason}]"
                            f"\n\n--- SDK message follows ---\n\n{text}"
                        )
                        self._last_interrupt_reason = None
                    kind = "tool-error" if msg.is_error else "tool-result"
                    await self._record_evidence(job, kind, text)
                    await self._log_truncated(
                        kind,
                        text,
                        600,
                        meta={
                            "tool_result": {
                                "tool_use_id": msg.tool_call_id,
                                "is_error": msg.is_error,
                            }
                        },
                    )
                    await self._record_jsonl(
                        kind,
                        {
                            "text": text,
                            "job_id": job.id,
                        },
                    )
                    await self._action_ledger_finish(msg, text, is_error=msg.is_error)
                    if msg.is_error:
                        self._pop_loop_entry_on_gate_refusal(msg.tool_call_id, text)
                elif isinstance(msg, NativeActionStartedEvent):
                    block = ToolCallContent(msg.id, msg.name, msg.arguments)
                    pretty = _prettify_tool_name(msg.name)
                    safe_input = _redact_secret_fields(msg.arguments, tool=msg.name)
                    label = f"{pretty}  {_format_tool_args(safe_input)}"
                    await self._log_truncated(
                        "tool-call",
                        label,
                        400,
                        meta={
                            "native_action": {
                                "id": msg.id,
                                "kind": msg.kind.value,
                                "name": pretty,
                                "input": safe_input,
                            },
                            # Also emit the provider-neutral tool_call identity the
                            # Claude path ships so stream consumers (TUI REPL pairing,
                            # web card) render native/MCP tool calls the same way.
                            "tool_call": {
                                "id": msg.id,
                                "name": pretty,
                                "input": safe_input,
                            },
                        },
                    )
                    # Persist to JSONL + the events DB table so `logs grep` and the
                    # `events` query surface native / MCP tool calls too — _log skips
                    # this for tool-* kinds, so (unlike Claude's ToolCallContent path)
                    # native actions were invisible to those views.
                    await self._record_jsonl(
                        "tool-call",
                        {
                            "tool": msg.name,
                            "tool_pretty": pretty,
                            "input": safe_input,
                            "label": label,
                            "job_id": job.id,
                        },
                    )
                    tool_uses_in_job += 1
                    self.tool_call_counts[pretty] += 1
                    await self._check_loop(msg.name, msg.arguments, tool_use_id=msg.id)
                    await self._action_ledger_start(job, block, pretty)
                elif isinstance(msg, NativeActionCompletedEvent):
                    result = ToolResultEvent(msg.id, msg.content, msg.is_error)
                    kind = "tool-error" if msg.is_error else "tool-result"
                    text = _format_tool_result(msg.content)
                    await self._record_evidence(job, kind, text)
                    await self._log_truncated(
                        kind,
                        text,
                        600,
                        meta={
                            "native_action_result": {
                                "id": msg.id,
                                "kind": msg.kind.value,
                                "is_error": msg.is_error,
                            },
                            "tool_result": {
                                "tool_use_id": msg.id,
                                "is_error": msg.is_error,
                            },
                        },
                    )
                    await self._record_jsonl(kind, {"text": text, "job_id": job.id})
                    await self._action_ledger_finish(result, text, is_error=msg.is_error)
                elif isinstance(msg, TurnCompletedEvent):
                    cost = msg.usage.cost_usd
                    in_t = msg.usage.input_tokens
                    out_t = msg.usage.output_tokens
                    cache_r = msg.usage.cache_read_tokens
                    cache_c = msg.usage.cache_create_tokens
                    self.total_input_tokens += in_t
                    self.total_output_tokens += out_t
                    self.total_cache_read_tokens += cache_r
                    self.total_cache_create_tokens += cache_c
                    if cost is not None:
                        self.total_cost_usd += cost
                    self.total_jobs_completed += 1
                    self.last_input_tokens = in_t
                    self.last_output_tokens = out_t
                    # Auto-checkpoint accumulator: total prompt tokens this turn
                    # (everything the model saw, regardless of cache hit). The
                    # threshold check happens in Daemon._on_job_complete so
                    # we don't need to know about it here.
                    self._tokens_since_checkpoint += in_t + cache_r + cache_c
                    tok_summary = f" tokens={in_t}/{out_t} (in/out)" if (in_t or out_t) else ""
                    cost_summary = f"${cost:.4f}" if cost is not None else "n/a"
                    await self._log(
                        "done",
                        f"turns={msg.turns} cost={cost_summary} "
                        f"duration={msg.duration_ms}ms{tok_summary}",
                        # Structured per-turn usage for stream consumers (the
                        # TUI REPL StatusBar). The numbers were previously only
                        # in the display text; expose them as data too.
                        meta={
                            "usage": {
                                "input_tokens": in_t,
                                "output_tokens": out_t,
                                "cache_read_tokens": cache_r,
                                "cache_create_tokens": cache_c,
                                "cost_usd": cost,
                            }
                        },
                    )
                elif isinstance(msg, ProviderErrorEvent):
                    job.error = f"{msg.code}: {msg.message}"
                    await self._log("tool-error", job.error)
                elif isinstance(msg, ContextCompactedEvent):
                    await self._log("system", msg.summary)
                else:
                    assert_never(msg)
            # Inner receive_response loop has ended (ResultMessage hit or
            # hard-cap break). Decide whether this phase was a "silent
            # completion" — no tool calls AND no <ask_operator> tag AND a
            # caller is awaiting our reply — and if so, re-prompt ONCE.
            if job.error is not None:
                break
            tools_this_phase = tool_uses_in_job - tools_before
            phase_text = "".join(chunks[chunks_before:])
            # An operator steer that interrupted this turn ends it early by
            # design — don't treat that as a silent completion to re-prompt.
            steer_truncated = self._steer_interrupt_pending
            self._steer_interrupt_pending = False
            # A text reply IS the deliverable — `job.result` (the accumulated
            # chunks) is returned to the awaiting caller, so an agent that answered
            # in prose never stranded anyone. Only nudge when the phase produced
            # NOTHING: no text, no tool call, no `<ask_operator>`. Without the
            # empty-text guard a delegated agent that simply answers (common on
            # codex, which reaches for tools/ask_operator less readily) gets
            # re-prompted and its reply is duplicated.
            silent = (
                not nudge_fired
                and not cap_fired
                and not steer_truncated
                and job.future is not None
                and tools_this_phase == 0
                and not phase_text.strip()
                and "<ask_operator>" not in phase_text
            )
            if not silent:
                break
            nudge_fired = True
            nudge_prompt = (
                "You just ended a turn with no tool calls and no "
                "`<ask_operator>` tag, and a caller is awaiting your "
                "reply on this job — ending silently strands them. "
                "If you are blocked or stuck, file an `<ask_operator>` "
                "right now describing what you need (the runner does "
                "not nudge twice, so this is the last automatic "
                "prompt). Otherwise produce the deliverable. Do not "
                "end silently."
            )
            await self._log("nudge", "silent-completion: re-prompting")
            await self._record_jsonl(
                "nudge",
                {
                    "job_id": job.id,
                    "reason": "silent-completion",
                    "turn_count": turn_count,
                },
            )
            await self._backend.query(_alias_outbound(nudge_prompt))
        job.result = "".join(chunks)
        # JSON-as-text fallback for endpoint-overridden agents. Local models
        # via LiteLLM/Ollama (llama3.x, etc.) often emit OpenAI-style
        # function-call JSON in plain text rather than producing native
        # Anthropic `tool_use` blocks — so the SDK's tool dispatcher never
        # fires and the operator just sees raw JSON in the reply. Detect
        # these embedded calls, route the supported ones to their bus
        # handlers, and strip the JSON from the visible reply.
        if self.cfg.get("endpoint") and job.result:
            await self._dispatch_text_function_calls(job)

    def submit(
        self,
        prompt: str,
        future: asyncio.Future | None = None,
        *,
        suppress_banner: bool = False,
        max_turns_hint: int | None = None,
        verification_leg: bool = False,
    ) -> Job:
        job = Job(
            id=self._next_job_id,
            prompt=prompt,
            submitted_at=time.time(),
            suppress_banner=suppress_banner,
            future=future,
            max_turns_hint=max_turns_hint,
            verification_leg=verification_leg,
        )
        self._next_job_id += 1
        # Don't queue against a dead OR stopping runner — fail the future
        # immediately so any awaiting bus call gets an error instead of waiting
        # for a job the loop will never pick up. `_stop_requested` (not just
        # status == "stopped") is the load-bearing check: the _run teardown
        # drains the queue and THEN awaits the SDK disconnect (routinely
        # 10-20s) before flipping status to "stopped", so during that window
        # status is still idle/busy while the loop has already exited. Guarding
        # on status alone would queue a job that strands the caller's future
        # until the bus reaper (prompt_timeout x3). submit() is synchronous up
        # to put_nowait, so checking _stop_requested here is race-free.
        if self.status == "stopped" or self._stop_requested:
            if future is not None and not future.done():
                future.set_exception(RuntimeError(f"{self.name}: cannot submit, agent is stopping"))
            return job
        self.queue.put_nowait(job)
        return job

    async def steer(self, text: str, *, interrupt: bool = False) -> bool:
        """Operator mid-run steering. Queues `text` to run AHEAD of any pending
        prompts (the priority lane), unlike submit() which appends to the FIFO
        queue.

        interrupt=True and a turn in flight → interrupt the current turn so the
        steer runs as the very next turn on the SAME conversation (context
        preserved; the in-flight partial turn is finalized first, attributed as
        an operator steer — NOT a tool rejection). interrupt=False → let the
        current turn finish, then run the steer at that boundary. Returns True
        iff the current turn was interrupted. No-op on a stopped/stopping
        runner — `_stop_requested` (not just status == "stopped") covers the
        teardown disconnect window where the loop has exited but status hasn't
        flipped yet, so a steer can't strand in the lane of a dead loop."""
        if self.status == "stopped" or self._stop_requested:
            return False
        job = Job(id=self._next_job_id, prompt=text, submitted_at=time.time())
        self._next_job_id += 1
        self._steer_lane.append(job)
        # Wake an idle (queue-blocked) loop so it drains the lane immediately.
        with suppress(Exception):
            self.queue.put_nowait(_STEER_WAKE)
        did_interrupt = False
        # Gate on _turn_active (a turn is actually streaming) — NOT
        # `current is not None`, which stays set through the post-turn
        # finalization window and would let a between-turns steer fire a
        # spurious interrupt + report interrupted=True for a no-op.
        if interrupt and self._turn_active and self._backend is not None:
            # Set the attribution BEFORE the interrupt so the SDK's synthetic
            # "doesn't want to proceed" ToolResultBlock is rewritten as an
            # operator steer rather than a tool refusal (see _process).
            self._last_interrupt_reason = (
                "OPERATOR STEER — the operator interrupted this turn to inject "
                "new guidance, delivered as your next turn on the same "
                "conversation. This is NOT a tool rejection; incorporate it."
            )
            with suppress(Exception):
                await self._backend.interrupt()
                did_interrupt = True
                self._steer_interrupt_pending = True
        return did_interrupt

    async def stop(self, *, kill: bool = False) -> None:
        self._stop_requested = True
        if kill and self._backend and self.current:
            self._last_interrupt_reason = (
                "RUNNER STOPPED — operator killed the agent via "
                "`salientctl kill` (or daemon shutdown). The SDK's "
                "'doesn't want to proceed' echo below is the wire-"
                "level cancellation, not a tool-use rejection."
            )
            with suppress(Exception):
                await self._backend.interrupt()
        # Nudge the queue.get() in _run if it's blocked.
        with suppress(Exception):
            self.queue.put_nowait(None)
        _log.info("agent %s stopped (kill=%s)", self.name, bool(kill))

    async def cancel_job(self, job_id: int) -> bool:
        """Stop one specific job by id. Returns True if it was found.

        In-flight (``self.current``): interrupt the SDK turn — gated on
        ``_turn_active`` exactly like steer(interrupt=True), so a cancel in
        the post-turn finalization window can't fire a spurious interrupt.
        Queued: drain the FIFO, drop the matching Job, requeue the rest in
        order (asyncio.Queue has no remove-by-predicate). The drain is
        await-free, so under single-threaded asyncio it's atomic w.r.t. the
        run loop — no queued job can be promoted to current mid-drain.

        Wired into ``bus_call_cancel`` so a cancelled delegation also stops the
        child burning tokens: settling the caller's future alone leaves the
        child running until its own timeout."""
        cur = self.current
        if cur is not None and cur.id == job_id:
            self._last_interrupt_reason = (
                "JOB CANCELLED — the operator cancelled the bus call that "
                "dispatched this job (`salientctl bus cancel`). The SDK's "
                "'doesn't want to proceed' echo below is the wire-level "
                "cancellation, not a tool-use rejection."
            )
            if (
                self._turn_active
                and self._backend is not None
                and self._interrupted_job_id != job_id
            ):
                # Record BEFORE the await so a re-entrant cancel_job for the same
                # job (concurrent reap owners) sees the guard and skips a second
                # interrupt.
                self._interrupted_job_id = job_id
                with suppress(Exception):
                    await self._backend.interrupt()
            return True
        # Queued: drain, drop the match, requeue the rest. Non-Job sentinels
        # (None shutdown / _STEER_WAKE) are preserved in their original order.
        found = False
        pending: list = []
        while True:
            try:
                item = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if isinstance(item, Job) and item.id == job_id:
                found = True
                # Normally already settled by bus_call_cancel before we run;
                # the guard makes a direct cancel_job() caller safe too, so a
                # dropped job's caller never leaks on its await.
                if item.future is not None and not item.future.done():
                    item.future.set_exception(
                        RuntimeError(f"{self.name}: job {job_id} cancelled before start")
                    )
                continue
            pending.append(item)
        for item in pending:
            self.queue.put_nowait(item)
        return found

    def _synthetic_dispatch(
        self,
        daemon: DaemonServices,
        bare: str,
        args: dict[str, Any],
    ) -> tuple[bool | None, str, str]:
        """Execute a single side-effect-only bus call synthesized from
        JSON-as-text. Returns (ok, result_text, args_for_log):

          ok=True   — dispatched, result_text is the bus tool's success line
          ok=False  — dispatched but the tool rejected the inputs
          ok=None   — tool name isn't in the side-effect-only allowlist

        Read-side tools (context_read, kg_query, prior_actions, etc.)
        deliberately return None: the model has already ended its turn,
        so feeding their result anywhere would be pointless.
        """
        if bare == "ask_operator":
            question = str(args.get("question", "")).strip()
            if not question:
                return False, "error: question is required", "question=(empty)"
            qid = daemon.add_question(self.name, question, job_id=None)
            return (
                True,
                f"Question Q{qid} queued for the operator (dispatched from JSON-as-text fallback).",
                f'question="{question}"',
            )
        if bare == "context_write":
            key = str(args.get("key") or "").strip()
            value = args.get("value")
            if not key:
                return False, "error: key is required", "key=(empty)"
            if not isinstance(value, str):
                return False, "error: value must be a string", f"key={key!r}"
            from ..alias import rewrite_inbound as _alias_inbound

            stored = _alias_inbound(value)
            if daemon.context is None:
                return False, "error: context store unavailable", f"key={key!r}"
            daemon.context.write(self.name, key, stored)
            return (
                True,
                f"wrote {self.name}/{key} ({len(stored)} chars)",
                f"key={key!r} ({len(stored)} chars)",
            )
        if bare == "kg_assert":
            s = str(args.get("subject") or "").strip()
            p = str(args.get("predicate") or "").strip()
            o = str(args.get("object") or "").strip()
            if not s or not p or not o:
                return (
                    False,
                    "error: subject, predicate, object all required",
                    "missing s/p/o",
                )
            try:
                conf = float(args.get("confidence", 1.0))
            except (TypeError, ValueError):
                conf = 1.0
            eng_id = daemon.engagement_path.name if daemon.engagement_path is not None else None
            try:
                fact = daemon.kg.assert_fact(
                    s,
                    p,
                    o,
                    confidence=conf,
                    agent=self.name,
                    engagement_id=eng_id,
                )
            except Exception as e:  # noqa: BLE001
                return (
                    False,
                    f"kg_assert error: {type(e).__name__}: {e}",
                    f"({s})-[{p}]->({o})",
                )
            return True, f"recorded: {fact}", f"({s})-[{p}]->({o})"
        if bare == "cred_record":
            kind = str(args.get("kind") or "").strip().lower()
            user = str(args.get("user") or "").strip()
            value = str(args.get("value") or "").strip()
            host = str(args.get("host") or "").strip().lower()
            source = str(args.get("source") or "").strip() or self.name
            try:
                conf = float(args.get("confidence", 1.0))
            except (TypeError, ValueError):
                conf = 1.0
            if kind not in cred_kinds():
                return (
                    False,
                    f"error: kind must be one of {sorted(cred_kinds())}, got {kind!r}",
                    f"user={user!r} kind={kind!r}",
                )
            if not user or not value:
                return (
                    False,
                    "error: user + value are required",
                    f"user={user!r}",
                )
            eng_id = daemon.engagement_path.name if daemon.engagement_path is not None else None
            subject = f"user:{user}"
            predicate = predicate_for_kind(kind)
            obj = f"secret:{kind}:{value}"
            try:
                daemon.kg.assert_fact(
                    subject,
                    predicate,
                    obj,
                    confidence=conf,
                    agent=source,
                    engagement_id=eng_id,
                )
                if host:
                    daemon.kg.assert_fact(
                        subject,
                        "works_against",
                        f"host:{host}",
                        confidence=conf,
                        agent=source,
                        engagement_id=eng_id,
                    )
            except Exception as e:  # noqa: BLE001
                return (
                    False,
                    f"cred_record error: {type(e).__name__}: {e}",
                    f"user={user!r} kind={kind!r}",
                )
            return (
                True,
                f"recorded credential for {user!r} ({kind})",
                f"user={user!r} kind={kind!r}" + (f" host={host!r}" if host else ""),
            )
        return None, "", ""

    async def _dispatch_text_function_calls(self, job: "Job") -> None:
        """Post-process a text reply from an endpoint-override agent to
        catch OpenAI-style function-call JSON the model emitted in text,
        dispatch the recognized bus calls, and clean up the visible reply.

        Also strips llama-3 output noise like `<|python_tag|>` prefixes,
        which the model emits when LiteLLM/Ollama translated its tool
        attempt back into the message stream.

        Only `ask_operator` is supported today — it's the only bus tool
        whose side-effect (queueing a question for the operator) makes
        sense after the model has already ended its turn. Other detected
        calls are logged as a `tool-fallback-unsupported` event and left
        in the reply text for the operator to see.

        When the model ALREADY filed an ask_operator via a native
        tool_use this turn, we don't re-dispatch any JSON-as-text or
        `<ask_operator>` tags we find — those are leftover noise from
        the same intent. Strip them silently and leave the visible
        reply clean.
        """
        daemon = getattr(self, "_daemon", None)
        if daemon is None:
            return
        # Did the native tool path already file an operator Q this turn?
        # If so, suppress dispatch and just clean up the leftover noise.
        already_filed_operator_q = bool(
            getattr(job, "tool_question_ids", None)
            and any(
                (q := daemon.inbox.get(qid)) is not None and q.kind == "operator"
                for qid in job.tool_question_ids
            )
        )
        original = _strip_llama_output_noise(job.result)
        calls, cleaned = _extract_function_calls_from_text(original)
        if not calls and original == job.result:
            return
        if already_filed_operator_q:
            # Strip the JSON / tag noise; don't re-dispatch.
            job.result = cleaned.strip() or job.result
            return
        if not calls:
            # Only the noise prefix was present; nothing to dispatch.
            job.result = original.strip() or job.result
            return
        dispatched = 0
        for raw_name, args in calls:
            # Names may arrive bare ("ask_operator") or MCP-qualified
            # ("mcp__bus__<agent>__ask_operator"). Normalize to bare.
            bare = raw_name.rsplit("__", 1)[-1] if "__" in raw_name else raw_name
            if bare not in {"ask_operator", "context_write", "kg_assert", "cred_record"}:
                # Tool isn't in the side-effect-only allowlist — surface
                # so the operator can see WHY their agent is producing
                # JSON gibberish, but don't try to fake the result back
                # to the model (the model already ended its turn).
                await self._log(
                    "tool-fallback-unsupported",
                    f"text-emitted call to {bare!r} not auto-dispatched "
                    "(read-side bus tools can't be synthesized after the model "
                    "ends its turn — its next call would consume nothing)",
                )
                continue
            invocation = ToolInvocation.normalize(text_identity(raw_name, self.name), args)
            authorization = await authorize_text(
                invocation,
                dataset=self._policy_dataset or get_active(),
                safeguards=self._safeguard_config,
                safeguard_count=self.total_safeguard_blocks,
                scope_store=self._scope_store,
                enforce=self._enforce_builtin_policy,
            )
            self.total_safeguard_blocks += authorization.counter_delta
            await self._record_jsonl(authorization.event, authorization.payload)
            if not authorization.dispatch_allowed:
                result_text = f"policy error: {authorization.reason}"
                await self._log("tool-error", _truncate(result_text, 200))
                await self._record_jsonl(
                    "tool-error",
                    {
                        "text": result_text,
                        "job_id": job.id,
                        "synthetic": True,
                    },
                )
                continue
            ok, result_text, args_for_log = self._synthetic_dispatch(daemon, bare, args)
            assert ok is not None
            label = (
                f"bus.{self.name}.{bare}(synthetic, from JSON-as-text)  "
                f"{_truncate(args_for_log, 200)}"
            )
            await self._log("tool-call", label)
            await self._record_jsonl(
                "tool-call",
                {
                    "tool": f"mcp__bus__{self.name}__{bare}",
                    "tool_pretty": f"bus.{self.name}.{bare}",
                    "input": args,
                    "label": label,
                    "job_id": job.id,
                    "synthetic": True,
                },
            )
            kind = "tool-result" if ok else "tool-error"
            await self._log(kind, _truncate(result_text, 200))
            await self._record_jsonl(
                kind,
                {
                    "text": result_text,
                    "job_id": job.id,
                    "synthetic": True,
                },
            )
            if ok:
                dispatched += 1
        if dispatched:
            stripped = cleaned.strip()
            if stripped:
                job.result = stripped
            else:
                job.result = (
                    f"(dispatched {dispatched} bus call(s) parsed from JSON-as-text fallback)"
                )
