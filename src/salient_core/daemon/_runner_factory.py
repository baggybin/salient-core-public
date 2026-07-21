"""Daemon mixin: runner factory + per-agent SDK option assembly + hooks.

Methods extracted from salient/daemon/core.py to keep the central
Daemon class navigable. All methods continue to access `self.X` exactly
as before — Daemon assembles them via multiple inheritance.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
from functools import partial

log = logging.getLogger(__name__)

# Warn-once set for the loop-detection question-filing path.
_LOOP_WARNED: set[str] = set()
from collections import deque
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, assert_never, cast
from urllib.parse import urlparse

from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

from ..bus import get_bus_builder, make_bus_tool_bundle, make_bus_tools
from ..policy.registry import PolicyDataset, get_active


# Engagement profile resolution is downstream SKIN (registered via
# set_daemon_skin_modules(engagement=...)). Resolved at call time; the kernel
# keeps permissive standalone defaults — nothing disabled, an empty profile
# block — so it runs without an engagement module, while effective_model REQUIRES
# one (there is no sensible default model).
def _effective_model(*args: Any, **kwargs: Any) -> Any:
    eng = get_daemon_skin_module("engagement", required=False)
    if eng is None:
        raise NotImplementedError("engagement module not registered (kernel-only mode)")
    return eng.effective_model(*args, **kwargs)


def _is_agent_disabled(*args: Any, **kwargs: Any) -> bool:
    eng = get_daemon_skin_module("engagement", required=False)
    return eng.is_agent_disabled(*args, **kwargs) if eng is not None else False


def render_profile_block(*args: Any, **kwargs: Any) -> str:
    eng = get_daemon_skin_module("engagement", required=False)
    return eng.render_profile_block(*args, **kwargs) if eng is not None else ""


from ..protocols import ToolBuildContext
from ..providers import ProviderName, get_provider_registry
from ..runtime import AgentBackend, ToolBundle
from ._backend import LocalClaudeBackend, _json_value
from ._helpers import (
    Job,
    _extract_marker_questions,
    _strip_question_markers,
    first_running_sibling_shadow,
)
from ._prompts import (
    _expand_envvars,
    _format_approval_block,
    _format_tools_block,
    _load_agent_protocol,
    _load_recipe_discipline,
    _load_shadow_discipline,
    resolve_endpoint_thinking,
)
from ._tasks import spawn_background
from ._tool_registry import (
    get_daemon_skin_module,
    get_subagent_builder,
    get_tool_builder,
    get_tool_bundle_builder,
)
from .runner import AgentRunner

if TYPE_CHECKING:
    from ..protocols import DaemonServices


# Cover the SDK disconnect (the runner documents it as "routinely 10-20s") so a
# restart's fresh runner doesn't overlap the old one's teardown.
_RESTART_DRAIN_TIMEOUT = 25.0


async def _drain_for_restart(r: Any) -> None:
    """Await a just-stopped runner's ``_run`` task so its teardown (SDK
    disconnect + JSONL close) finishes BEFORE a replacement starts on the SAME
    name — otherwise the old runner's ``finally`` races the new runner's start
    (JSONL handle + SDK subprocess for the same agent). Bounded +
    cancel-on-timeout so a wedged disconnect can't hang the restart. ONLY the
    restart paths call this; plain ``stop()`` / ``pause()`` / the panic
    killswitch stay fire-and-forget so they aren't serialized behind the
    ~10-20s disconnect."""
    task = getattr(r, "_task", None)
    if task is None or task is asyncio.current_task():
        return
    try:
        await asyncio.wait_for(task, timeout=_RESTART_DRAIN_TIMEOUT)
    except Exception:
        # Timeout (wait_for cancels the task) or a teardown error — best-effort.
        # A CancelledError (the restart itself being cancelled) still propagates.
        pass


# ── agent spawn/despawn observer seam ────────────────────────────────
# A downstream skin may need to attach a per-agent side-process when an agent
# starts and tear it down when it stops/restarts (e.g. a tool-backend watcher).
# The kernel exposes a single observer seam; the default is no observer, so the
# kernel starts and stops nothing beyond the runner itself. Registered once at
# startup, consulted at call time — the same idiom as the bus observer seams.
_spawn_observer: Any | None = None


def set_spawn_observer(observer: Any) -> None:
    """Register a per-agent spawn/despawn observer. The kernel calls
    ``observer.on_spawn(daemon, name, cfg, runner)`` when an agent starts and
    ``await observer.on_despawn(daemon, name)`` when it stops or restarts.
    Either method may be omitted. Default: no observer."""
    global _spawn_observer
    _spawn_observer = observer


class _RunnerFactoryMixin:
    def _notify_agent_spawn(self, name: str, cfg: dict[str, Any], runner: Any) -> None:
        """Fire the registered spawn observer, if any. Never raises into the
        spawn path — a broken skin observer must not stop an agent starting."""
        obs = _spawn_observer
        on_spawn = getattr(obs, "on_spawn", None) if obs is not None else None
        if on_spawn is None:
            return
        try:
            on_spawn(self, name, cfg, runner)
        except Exception:  # noqa: BLE001 — isolate a broken skin observer
            log.exception("spawn observer on_spawn failed for agent %s", name)

    async def _notify_agent_despawn(self, name: str) -> None:
        """Fire the registered despawn observer, if any. Mirror of
        _notify_agent_spawn; never raises into the stop/restart path."""
        obs = _spawn_observer
        on_despawn = getattr(obs, "on_despawn", None) if obs is not None else None
        if on_despawn is None:
            return
        try:
            await on_despawn(self, name)
        except Exception:  # noqa: BLE001 — isolate a broken skin observer
            log.exception("spawn observer on_despawn failed for agent %s", name)

    def _make_pre_compact_hook(self, agent_name: str):
        """Hook that fires when SDK auto-compaction (or manual `/compact`)
        triggers. Logs to the runner's tail so the operator sees that the
        SDK is folding older turns into a summary."""

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            data = dict(input_data) if input_data else {}
            trigger = data.get("trigger", "?")
            instructions = data.get("custom_instructions") or ""
            msg = f"compaction ({trigger})"
            if instructions:
                msg += f" — {instructions[:120]}"
            r = self.runners.get(agent_name)
            if r is not None:
                # Best-effort log to tail; don't fail the hook on emit error.
                try:
                    r._publish("compact", msg)
                except Exception:
                    pass
            return {}

        return hook

    def _make_prompt_safeguard_hook(
        self,
        agent_name: str,
        *,
        agent_cfg: dict[str, Any] | None = None,
        dataset: PolicyDataset | None = None,
    ):
        """UserPromptSubmit hook — scan the operator's prompt for
        natural-language prohibited-intent markers (restricted or
        high-impact requests, etc.).

        UserPromptSubmit's hook-specific output only adds context, while its
        top-level `decision: block` terminally refuses before Claude. This
        hook's job is:

          1. LOG-ONLY (default): emit a structured
             `safeguard_prompt_flag` event for visibility. The model
             still sees the prompt and decides what to do. Anthropic's
             own safeguards remain the enforcement floor.
          2. SOFT-REFUSE (`operator_prompt_mode: soft_refuse`):
             prepend a strong directive instructing the model to refuse
             the work and ask the operator to rephrase. Not a hard
             block, but the model honors directives reliably.
          3. HARD-REFUSE (`operator_prompt_mode: hard_refuse`): normally the
             runner gate already terminated the job. If a live config race or
             internal backend path reaches this hook, return the SDK's terminal
             block decision and record the match here as the sole observer.

        Either way, this fires BEFORE the operator's prompt becomes a
        tool call — the tool-level safeguard hook catches the actual
        action if any slips through.
        """
        runner_at_creation = self.runners.get(agent_name)
        captured_agent_cfg = copy.deepcopy(
            agent_cfg
            if agent_cfg is not None
            else ((runner_at_creation.cfg if runner_at_creation else None) or {})
        )
        captured_dataset = (
            dataset if dataset is not None else getattr(runner_at_creation, "_policy_dataset", None)
        )

        from ..policy.safeguards import (
            OperatorPromptMode,
            OperatorPromptModeError,
            check_prompt_intent,
            resolve_config,
        )

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            prompt = (input_data or {}).get("prompt") or ""
            if not isinstance(prompt, str) or not prompt.strip():
                return {}

            runner = self.runners.get(agent_name) or runner_at_creation
            try:
                cfg = resolve_config(captured_agent_cfg, self.profile)
            except OperatorPromptModeError:
                config_error_payload = {
                    "agent": agent_name,
                    "reason": "invalid_operator_prompt_mode",
                }
                if runner is not None:
                    runner._publish(
                        "safeguard_prompt_config_error",
                        "invalid safeguard configuration",
                        meta=config_error_payload,
                    )
                    await runner._record_jsonl(
                        "safeguard_prompt_config_error",
                        config_error_payload,
                    )
                return {
                    "decision": "block",
                    "reason": "invalid safeguard configuration",
                }

            match cfg.operator_prompt_mode:
                case OperatorPromptMode.HARD_REFUSE:
                    soft_refuse = True
                    redact_prompt = True
                    hard_enforcement = True
                case OperatorPromptMode.LOG:
                    soft_refuse = False
                    redact_prompt = False
                    hard_enforcement = False
                case OperatorPromptMode.SOFT_REFUSE:
                    soft_refuse = True
                    redact_prompt = False
                    hard_enforcement = False
                case unreachable:
                    assert_never(unreachable)

            allowed, reason = check_prompt_intent(
                prompt,
                config=cfg,
                dataset=captured_dataset,
            )
            if allowed:
                return {}

            # Counter is shared with tool-level blocks — same halt budget.
            # The model never sees a hard refuse, but the next tool call
            # will be cheaply refused once the threshold trips.
            if runner is not None:
                runner.total_safeguard_blocks += 1
                if hard_enforcement:
                    runner.total_prompt_hard_blocks += 1
            count = (
                runner.total_prompt_hard_blocks
                if runner is not None and hard_enforcement
                else (runner.total_safeguard_blocks if runner else 0)
            )

            if runner is not None:
                payload = {
                    "agent": agent_name,
                    "reason": reason,
                    "count": count,
                    "halt_at": cfg.halt_threshold,
                    "mode": cfg.operator_prompt_mode.value,
                }
                if not redact_prompt:
                    payload["prompt"] = prompt[:600]
                else:
                    runner._publish(
                        "safeguard_prompt_flag",
                        "operator prompt flagged",
                        meta=payload,
                    )
                await runner._record_jsonl(
                    "safeguard_prompt_flag",
                    payload,
                )

            if not soft_refuse:
                # LOG-ONLY — don't pollute the prompt; the visibility is
                # in the structured event for the operator.
                return {}

            if hard_enforcement:
                return {
                    "decision": "block",
                    "reason": "operator prompt blocked by safeguards",
                }

            # SOFT-REFUSE — prepend a directive the model honors.
            #
            # Sanitized: the specific matched pattern label (a
            # prohibited-intent marker name) is intentionally NOT in
            # the model-facing text — the model only needs to know the
            # call was refused, not the exact marker that matched. The
            # full reason is in the `safeguard_prompt_flag` JSONL event
            # for the operator.
            return {
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": (
                        "SAFEGUARD NOTICE: this operator prompt matched a "
                        "policy pattern the engagement profile is "
                        "configured to refuse. DO NOT proceed with the "
                        "requested work. Respond with a short explanation "
                        "of why the request appears to fall outside the "
                        "engagement's authorized scope, and ask the "
                        "operator to rephrase or confirm authorization "
                        "via <ask_operator>. Operator-side details are "
                        "logged."
                    ),
                }
            }

        return hook

    def _make_budget_chip_hook(self, agent_name: str):
        """PreToolUse hook that injects a `[budget: N/M]` chip into the
        model's view before each tool call — gives the agent a clear,
        structured turn-count signal instead of having to count
        conversation history.

        Background: 2026-05-16 audit showed a simple, bounded-task
        agent self-narrating "I'm at turn 2 — 13 left" in its
        thinking blocks. The complex multi-stage agents
        don't, because their task complexity drowns out the budget
        envelope's static "HARD CEILING of N turns" framing. This
        hook injects a fresh `[budget: N/M]` chip before every tool
        call so the count stays visible regardless of how busy the
        agent's reasoning is.

        Opt-in via `cfg.track_budget: true` to keep tokens free for
        agents that already self-track (single-shot tools).
        Skipped when the job has no `max_turns_hint` (operator-driven
        prompts have no ceiling to chip).

        Wording:
          turns_left > 2 → "[budget: N/M]"            (status)
          turns_left == 2 → "[budget: N/M — file <ask_operator> now
                              if no deliverable; proactive-escalation
                              turn per agent_protocol.md]"
          turns_left == 1 → "[budget: N/M — last turn, finalize NOW]"
          turns_left <= 0 → "[budget: N/M — OVER ceiling, finalize NOW]"
        """

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            runner = self.runners.get(agent_name)
            if runner is None:
                return {}
            job = getattr(runner, "current", None)
            if job is None:
                return {}
            m = getattr(job, "max_turns_hint", None)
            if not m:
                # No envelope budget → no chip. Operator-driven prompt.
                return {}
            n = int(getattr(runner, "current_turn_count", 0) or 0)
            turns_left = int(m) - n
            if turns_left <= 0:
                text = f"[budget: {n}/{m} — OVER ceiling, finalize NOW]"
            elif turns_left == 1:
                text = f"[budget: {n}/{m} — last turn, finalize NOW]"
            elif turns_left == 2:
                text = (
                    f"[budget: {n}/{m} — file <ask_operator> now if "
                    f"no deliverable; proactive-escalation turn per "
                    f"agent_protocol.md]"
                )
            else:
                text = f"[budget: {n}/{m}]"
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": text,
                }
            }

        return hook

    def _make_safeguard_hook(self, agent_name: str):
        """Apply universal safeguards and SDK-native authorization once."""

        from ..policy.registry import get_active
        from ..policy.safeguard_evaluation import (
            SafeguardEvaluationRequest,
            evaluate_safeguards,
        )
        from ..policy.safeguards import resolve_config
        from ..policy.scope_evaluation import ScopeEvaluationKind, evaluate_scope
        from ._policy_hook_adapter import (
            HookReplayCache,
            ReplayOutcome,
            ReplayOwner,
            ReplayRejected,
            deny,
            normalize_mcp,
            normalize_sdk,
            safeguard_payload,
            thaw_input,
        )

        replay_cache = HookReplayCache()

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            if not isinstance(input_data, dict):
                return {}
            tool_name = input_data.get("tool_name") or ""
            raw_tool_input = input_data.get("tool_input")
            tool_input = {} if raw_tool_input is None else raw_tool_input
            if not isinstance(tool_name, str) or not tool_name or not isinstance(tool_input, dict):
                return {}

            runner = self.runners.get(agent_name)
            agent_cfg = (runner.cfg if runner else None) or {}
            dataset = (
                runner._policy_dataset
                if runner is not None and runner._policy_dataset is not None
                else get_active()
            )
            cfg = (
                runner._safeguard_config
                if runner is not None
                else resolve_config(agent_cfg, self.profile)
            )
            if tool_name.startswith("mcp__"):
                rest = tool_name.removeprefix("mcp__")
                if "__" not in rest:
                    return {}
                server_name, bare_tool = rest.split("__", 1)
                if not server_name or not bare_tool:
                    return {}
                invocation = normalize_mcp(tool_name, tool_input, agent_name)
            else:
                invocation = normalize_sdk(tool_name, tool_input, agent_name)
            reservation = await replay_cache.reserve(tool_use_id, invocation)
            match reservation:
                case ReplayOutcome(outcome=outcome):
                    return outcome
                case ReplayRejected(reason=reason):
                    return deny(reason)
                case ReplayOwner() as owner:
                    pass
                case unreachable:
                    assert_never(unreachable)
            try:
                safeguards = evaluate_safeguards(
                    SafeguardEvaluationRequest(
                        invocation=invocation,
                        config=cfg,
                        current_strike_count=(runner.total_safeguard_blocks if runner else 0),
                        halt_threshold=cfg.halt_threshold,
                        dataset=dataset,
                    )
                )
                if runner is not None:
                    runner.total_safeguard_blocks += safeguards.counter_delta
                    if safeguards.audit is not None:
                        await runner._record_jsonl(
                            safeguards.audit.event.value,
                            safeguard_payload(safeguards.audit),
                        )
                if not safeguards.allowed:
                    return replay_cache.complete(
                        owner,
                        deny(safeguards.model_reason),
                    )
                if tool_name.startswith("mcp__"):
                    return replay_cache.complete(owner, {})

                evaluation = await evaluate_scope(invocation, self.scope, dataset)
                if evaluation.allowed:
                    return replay_cache.complete(owner, {})
                enforce = runner._enforce_builtin_policy if runner is not None else False
                if (
                    runner is not None
                    and not enforce
                    and evaluation.kind is ScopeEvaluationKind.UNCLASSIFIED
                    and tool_name in dataset.trusted_builtins
                    and runner.options.tools is not None
                    and tool_name in runner.options.tools
                    and tool_name not in runner._legacy_trusted_builtin_warned
                ):
                    async with runner._legacy_trusted_builtin_warning_lock:
                        if tool_name not in runner._legacy_trusted_builtin_warned:
                            await runner._record_jsonl(
                                "legacy_trusted_builtin",
                                {
                                    "agent": agent_name,
                                    "tool": tool_name,
                                    "qualified": invocation.qualified_name,
                                    "input": thaw_input(invocation.audit_input),
                                    "mode": "shadow",
                                    "deprecated": True,
                                    "migration": (
                                        "add an explicit qualified "
                                        "PolicyDataset.tool_targets classification "
                                        "before enabling enforce mode"
                                    ),
                                },
                            )
                            runner._legacy_trusted_builtin_warned.add(tool_name)
                if runner is not None:
                    await runner._record_jsonl(
                        "builtin_policy_deny" if enforce else "builtin_policy_shadow",
                        {
                            "agent": agent_name,
                            "tool": tool_name,
                            "qualified": invocation.qualified_name,
                            "policy_class": evaluation.kind.value,
                            "enforce": enforce,
                            "input": thaw_input(invocation.audit_input),
                            "reason": evaluation.reason,
                        },
                    )
                outcome = deny(evaluation.reason) if enforce else {}
                return replay_cache.complete(owner, outcome)
            finally:
                replay_cache.fail(owner)

        return hook

    def _make_read_containment_hook(self, agent_name: str):  # noqa: ARG002
        """PreToolUse hook confining the local file-reading built-ins (Read /
        Grep / Glob) to the study uploads tree (`work_root()/study`).

        The safeguard + external-scope hooks both early-return for any tool not
        prefixed `mcp__`, and scope.gate runs inside the MCP handler wrapper —
        so a built-in `Read` grant is otherwise COMPLETELY ungated and can open
        any path the daemon process can (engagement creds, scope DBs, other
        teams' work/). Registered ONLY for agents that opt in via
        `confine_reads_to_study` (the librarian) — never for general Read users
        like `bash`. The allowed root is resolved at call time so it honours
        SALIENT_WORK_ROOT, and the target is `resolve()`d (collapsing `..` and
        symlinks) before a trailing-separator prefix check, so neither path
        traversal nor a `study-evil` sibling can slip through."""
        config = get_daemon_skin_module("config")

        daemon = self
        read_tools = {"Read", "Grep", "Glob"}

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            tool_name = (input_data or {}).get("tool_name") or ""
            if tool_name not in read_tools:
                return {}
            ti = (input_data or {}).get("tool_input") or {}
            # A dispatch can NARROW the root to one project's uploads dir by
            # setting `_study_read_root` on the runner (study_extract does), so
            # the librarian on project A can't read project B's files. Falls
            # back to the whole study tree when unset.
            runner = daemon.runners.get(agent_name)
            override = getattr(runner, "_study_read_root", None) if runner else None
            allowed = (Path(override) if override else (config.work_root() / "study")).resolve()
            # Check EVERY path-bearing arg: file_path/path (Read/Grep), pattern
            # (Glob), glob (Grep) — a traversal pattern must not slip past a
            # valid base dir. Relative ones resolve against the base.
            base = ti.get("path") or ti.get("file_path") or ""
            candidates = [ti.get("file_path"), ti.get("path"), ti.get("pattern"), ti.get("glob")]
            offending = None
            for raw_c in candidates:
                if not raw_c:
                    continue
                try:
                    p = Path(raw_c)
                    target = (p if p.is_absolute() else Path(base or ".") / p).resolve()
                except (OSError, ValueError, RuntimeError):
                    offending = raw_c
                    break
                if not (target == allowed or str(target).startswith(str(allowed) + os.sep)):
                    offending = raw_c
                    break
            raw = offending if offending is not None else (base or "(no path)")
            ok = offending is None and any(candidates)
            if not ok:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"{tool_name} is confined to the study uploads tree "
                            f"({allowed}); {raw!r} is outside it. You may only "
                            f"read the document path handed to you."
                        ),
                    }
                }
            return {}

        return hook

    def _make_external_scope_hook(
        self,
        agent_name: str,
        external_servers: set[str],
    ):
        """PreToolUse hook that runs scope enforcement on tools coming
        from external MCP servers (Burp, future Caido / Mythic / etc.).

        Built-in factory tools already get scope enforcement via
        scope.gate wrapping their handlers at construction time. The
        SDK CLI hands every tool call through PreToolUse hooks before
        dispatch, so we use this path to gate the tools we DON'T own.

        Decision flow:
          1. If tool isn't an mcp__... call, return {} (no decision).
          2. Parse mcp__<server>__<tool>. If <server> isn't in
             `external_servers`, return {} (the factory wrapper handles
             it; double-gating would just duplicate the log row).
          3. Look up TOOL_TARGETS[<tool>]. If absent → fail-closed
             ("unclassified") to match scope.gate's policy.
          4. If spec.none → allow without logging. If spec.local_only →
             log allow, skip check. Else: extract_targets + store.check.
             On deny, return permissionDecision=deny with the refusal
             reason; on allow, return allow (so the SDK proceeds).
        """
        from ..policy.registry import get_active
        from ..policy.scope_evaluation import (
            ScopeEvaluationRequest,
            evaluate_scope,
        )
        from ._policy_hook_adapter import (
            HookReplayCache,
            ReplayOutcome,
            ReplayOwner,
            ReplayRejected,
            allow,
            deny,
            normalize_mcp,
        )

        replay_cache = HookReplayCache()

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            if not isinstance(input_data, dict):
                return {}
            tool_name = input_data.get("tool_name") or ""
            if not isinstance(tool_name, str):
                return {}
            if not tool_name.startswith("mcp__"):
                return {}
            rest = tool_name[len("mcp__") :]
            if "__" not in rest:
                return {}
            server_name, bare_tool = rest.split("__", 1)
            if not bare_tool or server_name not in external_servers:
                return {}
            raw_tool_input = input_data.get("tool_input")
            tool_input = {} if raw_tool_input is None else raw_tool_input
            if not isinstance(tool_input, dict):
                return {}
            runner = self.runners.get(agent_name)
            dataset = (
                runner._policy_dataset
                if runner is not None and runner._policy_dataset is not None
                else get_active()
            )
            invocation = normalize_mcp(tool_name, tool_input, agent_name)
            reservation = await replay_cache.reserve(tool_use_id, invocation)
            match reservation:
                case ReplayOutcome(outcome=outcome):
                    return outcome
                case ReplayRejected(reason=reason):
                    return deny(reason)
                case ReplayOwner() as owner:
                    pass
                case unreachable:
                    assert_never(unreachable)
            try:
                evaluation = await evaluate_scope(
                    invocation,
                    self.scope,
                    ScopeEvaluationRequest(dataset=dataset, allow_research=False),
                )
                if not evaluation.allowed:
                    return replay_cache.complete(owner, deny(evaluation.reason))
                return replay_cache.complete(owner, allow())
            finally:
                replay_cache.fail(owner)

        return hook

    def _make_subagent_approval_hook(self, agent_name: str):
        """PreToolUse hook that gates every SDK subagent spawn on operator
        approval.

        Added 2026-05-18 with the bus-redesign work: the operator wanted
        EVERY subagent spawn to require their approval — orchestrators
        can ASK (emit the Agent/Task tool call) but only the operator
        decides. This is stricter than `approve_before_delegate` (which
        bus_trusted callers bypass); subagent spawns always gate,
        regardless of bus_trusted status.

        Registered only on agents that DECLARE subagents (sub_defs
        truthy) — agents without subagents will never see Agent/Task
        tool calls, so the hook is unnecessary overhead.

        Tool-name match: the SDK renamed `Task` → `Agent` in Claude
        Code v2.1.63; we accept either to stay compatible across
        SDK versions (per Claude Agent SDK docs §"Detecting subagent
        invocation").

        Verdict translation:
          yes        → allow (no input modification)
          no <r>     → deny with the operator's reason
          edit: <p>  → allow with `updatedInput.prompt = <p>`
          timeout    → deny (no operator action within 10 min)
        """

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            tool_name = (input_data or {}).get("tool_name") or ""
            if tool_name not in ("Agent", "Task"):
                return {}  # only gate subagent spawns
            tool_input = (input_data or {}).get("tool_input") or {}
            subagent_type = tool_input.get("subagent_type") or "?"
            prompt = tool_input.get("prompt") or ""

            qid, fut_q = self.add_subagent_spawn_question(
                agent_name,
                subagent_type,
                prompt,
            )
            try:
                answer = await asyncio.wait_for(fut_q, timeout=600)
            except TimeoutError:
                # Match the agent_start / delegation gate timeout handlers
                # in bus.py — drop the pending registration, mark the
                # question answered, and publish so it doesn't loiter in the
                # operator inbox as an undeletable phantom.
                self.inbox.expire(qid, "[timed out]")
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"subagent approval Q{qid} timed out after "
                            f"10 min with no operator response — spawn refused. "
                            f"Try again when the operator is available, or "
                            f"use ask_agent for a single-target delegation."
                        ),
                    }
                }

            # Reuse the same parse as ask_agent's delegation gate.
            # `verdict` is one of "approve" / "deny" / "edit"; the
            # bus.py docstring on _parse_delegation_answer is the
            # source of truth.
            from ..bus import _parse_delegation_answer

            verdict, payload = _parse_delegation_answer(answer)

            if verdict == "approve":
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                    }
                }
            if verdict == "edit" and payload:
                # Operator wants the spawn to proceed but with a rewritten
                # prompt. Update the tool input before dispatch.
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": (f"operator edited Q{qid}"),
                        "updatedInput": {
                            **tool_input,
                            "prompt": payload,
                        },
                    }
                }
            # `no` (with or without reason) and any unrecognised verdict
            # → deny. The model sees the reason and can pivot.
            reason = payload or "no reason given"
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"operator denied subagent spawn (Q{qid}): {reason}. "
                        f"Try ask_agent for a long-lived Salient agent, "
                        f"ask_agents for a parallel swarm, or revise the "
                        f"subagent prompt and request again."
                    ),
                }
            }

        return hook

    def _make_approve_before_hook(self, agent_name: str):
        """PreToolUse hook that wire-enforces ``policy.approve_before``.

        Historically ``approve_before`` was prompt-only: a sentence in the
        agent's system prompt asking it to request operator approval before a
        dangerous action (see ``_prompts._format_approval_block``). A model that
        reasons around the prompt could run ``sudo`` / a destructive command /
        a restricted action ungated — the load-bearing safety seam that wasn't
        load-bearing (docs/STATUS.md §9). This hook makes the *declared* policy
        real: every tool call is classified (``action_class.classify_tool_action``)
        and any class in the agent's ``approve_before`` list blocks on operator
        approval before dispatch — the same future/question machinery the
        delegation and subagent gates use.

        Registered ONLY for agents that declare a non-empty ``approve_before``
        (the ~27 with a policy); everyone else pays nothing.

        Divergence from ``approve_before_delegate``: there is **no bus_trusted
        bypass**. ``bus_trusted`` is *delegation* trust (operator-extension for
        forwarding work); this gate is about an agent's own dangerous
        self-actions (sudo / destructive / restricted). If a policy lists ``sudo``,
        it gates regardless of trust posture.

        Verdict translation (reuses ``_parse_delegation_answer``):
          yes        → allow. For a destructive/sudo class on a command-bearing
                       tool, ``confirm_destructive=true`` is injected so the agent
                       needs no second round-trip.
          edit: <c>  → allow with the command replaced (command-bearing tools
                       only; otherwise deny with a note).
          no <r>     → deny with the operator's reason.
          timeout    → deny (deny-by-default — correct for a safety gate).
        """

        async def hook(input_data, tool_use_id, context):  # noqa: ARG001
            tool_name = (input_data or {}).get("tool_name") or ""
            tool_input = (input_data or {}).get("tool_input") or {}

            runner = self.runners.get(agent_name)
            agent_cfg = (runner.cfg if runner else None) or {}
            gated = set((agent_cfg.get("policy") or {}).get("approve_before") or [])
            if not gated:
                return {}  # no policy → nothing to gate (hook shouldn't be on)

            # Bare tool name: strip the `mcp__<server>__` prefix. The server is
            # the (aliased) agent name, so we key the safeguard lookup on the
            # tool TYPE + bare name instead — identical across a primary and its
            # shadows. SDK built-ins (Read/Bash/…) carry no prefix.
            if tool_name.startswith("mcp__"):
                rest = tool_name[len("mcp__") :]
                if "__" not in rest:
                    return {}
                _server, bare_tool = rest.split("__", 1)
            else:
                bare_tool = tool_name
            tool_type = (agent_cfg.get("tool") or {}).get("type")

            classify_tool_action = get_daemon_skin_module("action_class").classify_tool_action

            hit = gated & classify_tool_action(tool_type, bare_tool, tool_input)
            if not hit:
                return {}

            # Operator-facing summary of what's proposed.
            if "credentialed_browse" in hit:
                # Spell out the account-safety stakes; the operator is
                # authorizing use of THEIR OWN third-party login. Cookies/
                # session state never reach tool_input (resolved from disk by
                # host inside the tool), so nothing secret is in this text.
                _url = str(tool_input.get("url") or "").strip() or "(no url)"
                _host = urlparse(_url).hostname or _url
                summary = (
                    f"AUTHENTICATED render of {_url} — logs in AS YOU to "
                    f"{_host} using your saved session for that site. "
                    f"Aggressive use can get that account rate-limited / "
                    f"flagged / banned."
                )
            else:
                cmd = tool_input.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    summary = cmd.strip()
                else:
                    summary = (
                        ", ".join(f"{k}={v!r}" for k, v in list(tool_input.items())[:6])
                        or "(no args)"
                    )
            if len(summary) > 300:
                summary = summary[:299] + "…"

            if runner is not None:
                await runner._record_jsonl(
                    "approve_before_gate",
                    {
                        "agent": agent_name,
                        "tool": tool_name,
                        "bare": bare_tool,
                        "categories": sorted(hit),
                        "input": tool_input,
                    },
                )

            qid, fut_q = self.add_tool_approval_question(
                agent_name,
                bare_tool,
                summary,
                sorted(hit),
            )
            try:
                answer = await asyncio.wait_for(fut_q, timeout=600)
            except TimeoutError:
                self.inbox.expire(qid, "[timed out]")
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"operator approval Q{qid} timed out after 10 min — "
                            f"action refused (this call needs operator approval: "
                            f"{', '.join(sorted(hit))}). Surface it to the "
                            f"operator and retry when they're available."
                        ),
                    }
                }

            from ..bus import _parse_delegation_answer

            verdict, payload = _parse_delegation_answer(answer)

            inject_confirm = bool({"destructive", "sudo"} & hit and "command" in tool_input)
            if verdict == "approve":
                if inject_confirm:
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow",
                            "permissionDecisionReason": f"operator approved Q{qid}",
                            "updatedInput": {**tool_input, "confirm_destructive": True},
                        }
                    }
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                    }
                }
            if verdict == "edit" and payload:
                if "command" not in tool_input:
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
                                f"operator edit on Q{qid} isn't supported for "
                                f"this tool (no `command` field) — re-issue the "
                                f"call yourself or ask for yes/no."
                            ),
                        }
                    }
                edited = {**tool_input, "command": payload}
                if inject_confirm:
                    edited["confirm_destructive"] = True
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": f"operator edited Q{qid}",
                        "updatedInput": edited,
                    }
                }
            reason = payload or "no reason given"
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"operator denied this action (Q{qid}): {reason}. "
                        f"Try a different approach, or revise and request again."
                    ),
                }
            }

        return hook

    @staticmethod
    def _wire_external_mcp_servers(
        spec: dict[str, Any],
        mcp_servers: dict[str, Any],
        *,
        env_inject: dict[str, str] | None = None,
        warn: Callable[[str], None] = print,
    ) -> list[str]:
        """Translate agents.yaml `mcp_servers:` entries into SDK MCP
        server configs and return the allowed_tools wires to add.

        Accepted entry shapes (`type` is required):

            mcp_servers:
              burp:
                type: sse                            # or "http"
                url: http://127.0.0.1:9876/sse
                headers: { Authorization: "..." }    # optional
                tools: "*"                           # or [list, of, names]
              burp_proxy:
                type: stdio
                command: java
                args: ["-jar", "/path/to/mcp-proxy.jar", "--sse-url", "..."]
                env: { FOO: "bar" }                  # optional
                tools: ["proxy_history", "send_to_repeater"]

        `tools` controls allowed_tools:
          - "*" (default): one glob `mcp__<name>__*` — the CLI matches
            every tool the server exposes. Convenient but trusts the
            external server's surface entirely.
          - list: explicit `mcp__<name>__<tool>` entries — tighter, but
            you must keep the list in sync with the server.

        Mutates `mcp_servers` in place. Bad entries are skipped with a
        loud printed warning rather than failing startup — better to
        come up degraded than to lose the whole daemon over one
        misconfigured server.
        """
        if not isinstance(spec, dict):
            return []
        wires: list[str] = []
        for name, raw in spec.items():
            if not isinstance(name, str) or not name.strip():
                warn(f"[daemon] WARN: mcp_servers entry has bad name {name!r}, skipping")
                continue
            if name in mcp_servers:
                warn(
                    f"[daemon] WARN: mcp_servers entry {name!r} collides "
                    f"with a built-in server, skipping"
                )
                continue
            if not isinstance(raw, dict):
                warn(f"[daemon] WARN: mcp_servers[{name!r}] is not a dict, skipping")
                continue
            kind = (raw.get("type") or "").strip().lower()
            # Build the SDK-shaped config dict. We don't import McpStdio/
            # McpSSEServerConfig — they're TypedDicts; a plain dict
            # matching the shape is accepted.
            cfg: dict[str, Any] = {}
            if kind in ("sse", "http"):
                url = (raw.get("url") or "").strip()
                if not url:
                    warn(
                        f"[daemon] WARN: mcp_servers[{name!r}] type={kind!r} "
                        f"missing 'url', skipping"
                    )
                    continue
                cfg["type"] = kind
                cfg["url"] = url
                if isinstance(raw.get("headers"), dict):
                    cfg["headers"] = {str(k): str(v) for k, v in raw["headers"].items()}
            elif kind == "stdio":
                command = (raw.get("command") or "").strip()
                if not command:
                    warn(
                        f"[daemon] WARN: mcp_servers[{name!r}] type='stdio' "
                        f"missing 'command', skipping"
                    )
                    continue
                cfg["type"] = "stdio"
                cfg["command"] = command
                if isinstance(raw.get("args"), list):
                    cfg["args"] = [str(a) for a in raw["args"]]
                # Merge env: daemon-injected defaults (env_inject) first,
                # user-config env in agents.yaml wins on collision. Lets the
                # daemon push SALIENT_EVIDENCE_CACHE into the stdio child
                # (e.g. the mcp_truncate_shim) without yaml plumbing.
                _env_raw = raw.get("env")
                env_user = _env_raw if isinstance(_env_raw, dict) else {}
                merged_env: dict[str, str] = {}
                if env_inject:
                    merged_env.update({str(k): str(v) for k, v in env_inject.items()})
                merged_env.update({str(k): str(v) for k, v in env_user.items()})
                if merged_env:
                    cfg["env"] = merged_env
            else:
                warn(
                    f"[daemon] WARN: mcp_servers[{name!r}] has unsupported "
                    f"type={kind!r} (expected sse / http / stdio), skipping"
                )
                continue
            mcp_servers[name] = cfg
            # allowed_tools wires
            tools_spec = raw.get("tools", "*")
            if tools_spec == "*" or tools_spec is None:
                wires.append(f"mcp__{name}__*")
            elif isinstance(tools_spec, list):
                for t in tools_spec:
                    if isinstance(t, str) and t.strip():
                        wires.append(f"mcp__{name}__{t.strip()}")
            else:
                warn(
                    f"[daemon] WARN: mcp_servers[{name!r}].tools must be "
                    f"'*' or a list, got {type(tools_spec).__name__}; "
                    f"defaulting to wildcard"
                )
                wires.append(f"mcp__{name}__*")
        return wires

    def _agent_work_dir(self, agent_name: str) -> Path:
        """Working directory for an agent's file-writing builtin tools (the
        SDK Bash/Write tools, codex file ops). Inside an engagement everything
        co-locates under the engagement dir. With NO engagement active, fall
        back to a dedicated per-agent scratch dir under
        ``$SALIENT_AGENT_SCRATCH`` (default ``~/.salient/scratch``) — NEVER the
        daemon's process cwd, which would let an agent dump files (recon
        output, ``curl -o`` dumps, notes) straight into wherever the daemon was
        launched, typically the source tree.

        The per-agent subdir keeps two agents' identically-named artifacts
        (e.g. a target-named ``<handle>.txt``) from colliding. Created 0700 so
        recon output isn't world-readable. Best-effort: on a mkdir failure we
        drop to the scratch root rather than the source tree."""
        if self.engagement_path is not None:
            return Path(self.engagement_path)
        base = (os.environ.get("SALIENT_AGENT_SCRATCH") or "").strip()
        root = Path(base).expanduser() if base else (Path.home() / ".salient" / "scratch")
        safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in agent_name) or "_agent"
        d = root / safe
        try:
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        except OSError:
            try:
                root.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            d = root
        return d

    def _build_options(
        self,
        cfg: dict[str, Any],
        *,
        stderr_callback: Any | None = None,
    ) -> ClaudeAgentOptions:
        mcp_servers: dict[str, Any] = {}
        allowed: list[str] = []
        if cfg.get("tool"):
            tool_cfg = cfg["tool"]
            # Copy + inject engagement context so factories that write
            # artifacts/outputs/logs can co-locate with the rest of the
            # engagement. The leading underscore signals "daemon-injected,
            # not user-config." Factories without need just ignore it.
            factory_config = dict(tool_cfg.get("config") or {})
            if self.engagement_path is not None:
                factory_config.setdefault("_engagement_path", str(self.engagement_path))
            # Inject the daemon-scoped listener registry for any tool
            # factory that wants to spawn tracked external listeners
            # (a downstream tool factory may need this). Leading underscore
            # signals daemon-injected. Factories that don't need it
            # ignore the key.
            factory_config.setdefault("_listener_registry", self.listeners)
            # Reverse-WSS worker hub, daemon-injected so the remote-worker tool
            # factory can forward remote.* calls to the enrolled worker. The
            # `session_id` comes from the agent's own tool.config; the hub is the
            # shared object (None when the hub isn't running). Leading underscore
            # signals daemon-injected; factories that don't need it ignore it.
            factory_config.setdefault("_worker_hub", getattr(self, "worker_hub", None))
            # Engagement posture (stealth/normal/loud), daemon-injected so
            # rate-bearing factories can pick a
            # conservative default. The safeguard hook's loud-technique
            # gate reads the same value via resolve_config. Leading
            # underscore signals daemon-injected; factories ignore it if
            # they don't care.
            from ..policy.safeguards import posture_from_profile

            factory_config.setdefault("_posture", posture_from_profile(self.profile))
            # Per-agent subprocess launch profile — the agent-level `launch:`
            # block (privilege/capability isolation for tool subprocesses),
            # daemon-injected as an OPAQUE pass-through. The kernel does not
            # interpret it; the tool layer (the security skin) resolves it to a
            # concrete launcher. Leading underscore signals daemon-injected;
            # factories/skins that don't isolate ignore the key. Note it comes
            # from `cfg` (agent-level), not `tool_cfg["config"]`.
            _launch = cfg.get("launch")
            if _launch:
                factory_config.setdefault("_launch_profile", _launch)
            # Authed-browsing master switch (engagement.yaml
            # `browser.authed_sessions`), daemon-injected so websearch's
            # browser_render_authed stays inert unless the engagement
            # explicitly opts in — defense-in-depth atop the per-call
            # operator-approval gate. Leading underscore signals
            # daemon-injected; factories ignore it if they don't care.
            _browser_cfg = (self.profile or {}).get("browser") or {}
            factory_config.setdefault("_authed_sessions", bool(_browser_cfg.get("authed_sessions")))
            # In-scope network CIDRs (direction=in, kind=network — single IPs
            # are normalized to /32 networks by parse_rule). Daemon-injected so
            # network-routing factories can auto-route ONLY
            # in-scope subnets through a tunnel. Leading underscore signals
            # daemon-injected; factories ignore it if they don't care.
            if getattr(self, "scope", None) is not None:
                factory_config.setdefault(
                    "_scope_networks",
                    [
                        r.pattern
                        for r in self.scope.rules()
                        if r.direction == "in" and r.kind == "network"
                    ],
                )
            # Server name aliased on the SDK side so Claude's tool
            # catalog reads `mcp__<alias>__*` instead of leaking the
            # raw agent name (e.g. an internal tool name) on every turn.
            # `agent_name=cfg["name"]` stays real — the scope-gate's
            # audit log is operator-visible and should show the real
            # agent that issued the call. The PreToolUse safeguard +
            # scope hooks reverse-alias the server name before lookup
            # so downstream tables (TOOL_TARGETS, PROHIBITED_PATTERNS)
            # stay keyed on real names.
            from ..alias import to_wire as _alias_to_wire

            wire_server_name = _alias_to_wire(cfg["name"])
            # Build the bus tool closure list once and register it on
            # BOTH the tool-type server (here) and the bus server
            # (below). See bus.make_bus_tools for the why; tl;dr
            # Claude occasionally drops the `bus__` namespace segment
            # for read_evidence / ask_agent / context_* and we'd
            # rather a no-op success than a tool_use_error.
            extra_bus_tools, extra_bus_wires = make_bus_tools(
                cast("DaemonServices", self), cfg["name"]
            )
            server, sname, wires = get_tool_builder()(
                tool_cfg["type"],
                factory_config,
                server_name=wire_server_name,
                scope_store=self.scope,
                agent_name=cfg["name"],
                extra_tools=extra_bus_tools,
                extra_bare_wires=extra_bus_wires,
            )
            mcp_servers[sname] = server
            allowed.extend(wires)
        sub_defs = get_subagent_builder()(
            cfg["name"],
            cfg.get("subagents") or [],
            mcp_servers,
            scope_store=self.scope,
        )
        # Gate (added 2026-05-18 with ask_agents redesign): SDK
        # subagents are a Claude-Anthropic feature — they ride on the
        # SDK's Agent/Task tool which requires the
        # `task-budgets-2026-03-13` beta header for budget control and
        # uses tool-shape conventions Anthropic's API guarantees. DeepSeek
        # /anthropic endpoint IGNORES all anthropic-beta headers and
        # other niceties; LiteLLM/Ollama proxies are similar. Drop
        # subagents silently with a warning rather than letting them
        # half-work — partial activation produces opaque failure modes
        # in the model's reasoning trace.
        if cfg.get("endpoint") and sub_defs:
            log.warning(
                "agent %r: declared %d subagent(s) but is endpoint-routed "
                "(endpoint=%s); dropping subagents because the SDK's Agent "
                "tool relies on beta headers that third-party proxies don't "
                "honour. Move subagents to a Claude-routed agent, or remove "
                "the `subagents:` block from this config.",
                cfg["name"],
                len(sub_defs),
                (cfg.get("endpoint") or {}).get("base_url", "?"),
            )
            sub_defs = []
        # Built-in Claude Code tools to enable. Default empty: agent's only
        # action surface is the namespaced MCP tool we provisioned (so our
        # destructive-pattern guard / sandbox apply). Per-agent opt-in via
        # `builtin_tools: [Read, Bash, Grep, ...]` in agents.yaml.
        builtin_tools: list[str] = list(cfg.get("builtin_tools") or [])
        if sub_defs:
            for t in ("Task", "Agent"):
                if t not in builtin_tools:
                    builtin_tools.append(t)
        # Auto-approve every enabled built-in so we don't get permission
        # prompts in the daemon (which has nowhere to display them).
        for t in builtin_tools:
            if t not in allowed:
                allowed.append(t)
        # Per-agent bus server for inter-agent communication. Built via the
        # registered bus builder (default: make_bus) so a skin can wrap it.
        bus_server, bus_name, bus_wires = get_bus_builder()(
            cast("DaemonServices", self), cfg["name"]
        )
        mcp_servers[bus_name] = bus_server
        allowed += bus_wires
        # Opt-in sim MCP server (scenario simulator + live snapshot).
        # Off by default — operator/debug agents flip it on with
        # `expose_sim_tools: true` in their cfg.
        if cfg.get("expose_sim_tools"):
            from salient.sim.mcp_tools import make_sim_tools

            sim_server, sim_name, sim_wires = make_sim_tools(self, cfg["name"])
            mcp_servers[sim_name] = sim_server
            allowed += sim_wires
        # External MCP servers declared in agents.yaml under
        # `mcp_servers: { <name>: { type: sse|stdio, ... } }`. We pass
        # the config dict through to the SDK as-is — kept narrow so
        # Salient doesn't grow a monolithic surface; future MCP
        # integrations (custom toolservers) reuse the
        # same passthrough. See _wire_external_mcp_servers for the
        # validation + allowed_tools merge.
        # Inject SALIENT_EVIDENCE_CACHE into stdio MCP children so a shim
        # (e.g. salient.mcp_truncate_shim) knows where to stash truncated
        # payloads. Mirrors the cache_dir we hand to internal factory tools
        # in tools.py:7474.
        env_inject: dict[str, str] = {}
        if self.engagement_path is not None:
            env_inject["SALIENT_EVIDENCE_CACHE"] = str(
                Path(self.engagement_path) / "evidence_cache"
            )
        # Merge step: plugins from <repo>/mcp_plugins + ~/.salient/mcp
        # that auto-attach to this agent get spliced in. Agent-yaml
        # entries win on key collision — a hand-written mcp_servers:
        # block can override / shadow a plugin manifest without
        # removing the manifest file. See salient/plugins.py.
        agent_yaml_mcp = dict(cfg.get("mcp_servers") or {})
        plugin_mcp: dict[str, Any] = {}
        registry = getattr(self, "plugins", None)
        if registry is not None:
            _plugins = get_daemon_skin_module("plugins")
            _to_entry = _plugins.manifest_to_mcp_servers_entry
            _matching = _plugins.matching_manifests

            agent_role = cfg.get("role") or self._role_for(cfg["name"], cfg)
            for m in _matching(registry, cfg["name"], agent_role):
                if m.name in agent_yaml_mcp:
                    continue  # explicit agents.yaml entry wins
                entry = _to_entry(m)
                # Manifests that opt into `scope_origins_flag` (browser-style
                # servers, e.g. mcp_plugins/browser.yaml) get the engagement's
                # in-scope origins appended to the stdio args, confining the
                # server to scope at the process level. Fail-safe: no scope
                # store → a non-matching sentinel so the server reaches nothing.
                flag = getattr(m, "scope_origins_flag", None)
                if flag and entry.get("type") == "stdio":
                    store = getattr(self, "scope", None)
                    origins = (
                        store.in_scope_origins() if store is not None else "https://scope.invalid"
                    )
                    entry["args"] = [*entry.get("args", []), flag, origins]
                plugin_mcp[m.name] = entry
        merged_mcp = {**plugin_mcp, **agent_yaml_mcp}
        external_wires = self._wire_external_mcp_servers(
            merged_mcp,
            mcp_servers,
            env_inject=env_inject,
        )
        allowed += external_wires
        # Track which server names came from external `mcp_servers:`
        # config — the PreToolUse hook gates ONLY those (built-in
        # factory tools are gated by their handler wrappers in
        # scope.gate; double-gating would be redundant logging).
        external_server_names: set[str] = set()
        for w in external_wires:
            # w is "mcp__<name>__*" or "mcp__<name>__<tool>"
            if w.startswith("mcp__"):
                rest = w[len("mcp__") :]
                if "__" in rest:
                    external_server_names.add(rest.split("__", 1)[0])
        # Resolve effective model: engagement override → agents.yaml → SDK default.
        model, _src = _effective_model(self.profile, cfg["name"], cfg)
        # max_turns: hard upper bound on assistant turns per submitted job.
        # SDK default is permissive; without a cap we've seen webapp jobs
        # run 44 turns, mostly re-iterating on accumulated context.
        # Per-agent override via `max_turns` in agents.yaml.
        max_turns = int(cfg.get("max_turns", 30))
        hooks_cfg: dict[str, list[HookMatcher]] = {
            # Surface SDK-level auto-compaction events to operator visibility.
            "PreCompact": [
                HookMatcher(hooks=[self._make_pre_compact_hook(cfg["name"])]),
            ],
        }
        # PreToolUse layers:
        #   1. safeguards — prohibited-use pattern detection (always on,
        #      covers internal factory tools, external MCPs, and bus
        #      tools). Cheap regex sweep; only fires on explicit matches.
        #   2. external scope — host scope enforcement for tools
        #      from external MCP servers (internal factory tools get
        #      scope.gate via their handler wrapper, so this layer is
        #      only needed when external_server_names is non-empty).
        #   3. budget chip (opt-in via cfg.track_budget) — injects
        #      `[budget: N/M]` additionalContext before every tool
        #      call so multi-stage agents keep the
        #      turn count visible without relying on prose teaching.
        pre_tool_hooks: list[HookMatcher] = [
            HookMatcher(hooks=[self._make_safeguard_hook(cfg["name"])]),
        ]
        if external_server_names:
            pre_tool_hooks.append(
                HookMatcher(
                    hooks=[
                        self._make_external_scope_hook(cfg["name"], external_server_names),
                    ]
                )
            )
        if cfg.get("track_budget"):
            pre_tool_hooks.append(
                HookMatcher(
                    hooks=[
                        self._make_budget_chip_hook(cfg["name"]),
                    ]
                )
            )
        # Read-containment — confine local file-reading built-ins to the study
        # uploads tree. Opt-in per agent (the librarian), NOT auto-applied to
        # every Read user (bash legitimately reads anywhere). Built-ins bypass
        # the safeguard/scope hooks, so this is the only gate on them.
        if cfg.get("confine_reads_to_study"):
            pre_tool_hooks.append(
                HookMatcher(
                    hooks=[
                        self._make_read_containment_hook(cfg["name"]),
                    ]
                )
            )
        # Subagent spawn approval (added 2026-05-18 with bus-redesign).
        # Only register on agents that actually have subagents declared
        # — agents without sub_defs will never emit Agent/Task tool
        # calls, so the hook would be dead weight. The hook gates EVERY
        # subagent spawn on operator approval regardless of caller
        # trust posture (operator's explicit preference: "they can ask
        # but only me [approve]"). This is stricter than
        # `approve_before_delegate` — the strictness lives entirely
        # inside the hook body, not here.
        if sub_defs:
            pre_tool_hooks.append(
                HookMatcher(
                    hooks=[
                        self._make_subagent_approval_hook(cfg["name"]),
                    ]
                )
            )
        # approve_before wire enforcement (closes docs/STATUS.md §9 #1).
        # Only register when the agent declares a non-empty approve_before —
        # the ~108 agents with `[]` never construct the hook. The hook
        # classifies each tool call (action_class) and blocks any class in
        # the policy on operator approval before dispatch. It applies to the
        # agent's own dangerous self-actions regardless of trust posture (no
        # bypass); the rationale lives in _make_approve_before_hook's docstring.
        if (cfg.get("policy") or {}).get("approve_before"):
            pre_tool_hooks.append(
                HookMatcher(
                    hooks=[
                        self._make_approve_before_hook(cfg["name"]),
                    ]
                )
            )
        hooks_cfg["PreToolUse"] = pre_tool_hooks
        # UserPromptSubmit — prompt-level safeguard, complementary to
        # tool-level. Default LOG-ONLY (additionalContext untouched);
        # `safeguards.operator_prompt_mode: soft_refuse` flips to a
        # model-side additionalContext directive. Hard refusal happens at
        # the transport-neutral runner boundary before backend dispatch.
        hooks_cfg["UserPromptSubmit"] = [
            HookMatcher(
                hooks=[
                    self._make_prompt_safeguard_hook(
                        cfg["name"],
                        agent_cfg=cfg,
                        dataset=get_active(),
                    )
                ]
            ),
        ]
        opt_kwargs: dict[str, Any] = {
            "system_prompt": self._augment_system_prompt(cfg),
            "mcp_servers": mcp_servers,
            "allowed_tools": allowed,
            "tools": builtin_tools,
            # Confine builtin file tools to a dedicated dir (engagement dir, or
            # a per-agent scratch dir) so relative writes never land in the
            # daemon's launch cwd / source tree. See _agent_work_dir.
            "cwd": str(self._agent_work_dir(cfg["name"])),
            "agents": sub_defs or None,
            "max_turns": max_turns,
            "hooks": hooks_cfg,
        }
        if model:
            opt_kwargs["model"] = model
        # Effort precedence — resolved via engagement.effective_effort
        # so the per-agent `efforts.<name>` override in the engagement
        # profile actually takes effect (the prior inline lookup only
        # honored the top-level `effort:` key). Full chain:
        #   agents.yaml `effort:`
        #   engagement `efforts.<name>`
        #   engagement top-level `effort:`
        #   daemon-wide --effort flag
        #   SDK default ("high")
        # The SDK accepts: low | medium | high | xhigh | max.
        _effective_effort = get_daemon_skin_module("engagement").effective_effort

        effort, _src = _effective_effort(
            self.profile,
            cfg["name"],
            cfg,
            daemon_default=self.global_effort,
        )
        if effort:
            opt_kwargs["effort"] = effort
        # Per-agent endpoint override. When the agent's yaml declares an
        # `endpoint:` block, route this agent's SDK subprocess through a
        # different inference endpoint (typically a LiteLLM proxy in
        # front of a local model) while the daemon as a whole stays on
        # whatever ANTHROPIC_* env vars are exported globally. Agents
        # without an `endpoint:` block fall through to the daemon's
        # inherited environment (Max-sub OAuth or normal API key).
        #
        # Shape:
        #   endpoint:
        #     base_url: http://192.168.1.94:4000      # required
        #     api_key:  sk-...                         # optional, but
        #                                              # most local proxies
        #                                              # require some key
        #     bare:     true                           # default: true.
        #                                              # passes --bare to
        #                                              # the SDK subprocess
        #                                              # so it skips MCP
        #                                              # plugin sync, keychain
        #                                              # reads, OAuth fallback,
        #                                              # background prefetches —
        #                                              # all of which try to
        #                                              # reach api.anthropic.com
        #                                              # / mcp-proxy.anthropic.com
        #                                              # and hang the agent
        #                                              # loop when talking to a
        #                                              # local model.
        endpoint_cfg = cfg.get("endpoint") or {}
        if endpoint_cfg:
            sub_env = dict(os.environ)
            # Drop the Claude Code attribution header on local / third-party
            # endpoints (LM Studio, LiteLLM, DeepSeek, MiniMax). It's
            # Anthropic-specific metadata these servers don't need, and the
            # LM Studio docs call for disabling it explicitly.
            sub_env["CLAUDE_CODE_ATTRIBUTION_HEADER"] = "0"
            base_url = _expand_envvars(endpoint_cfg.get("base_url"))
            api_key = _expand_envvars(endpoint_cfg.get("api_key"))
            if base_url:
                sub_env["ANTHROPIC_BASE_URL"] = base_url
            if api_key:
                # auth_style picks the header the SDK uses. "bearer"
                # (MiniMax's Anthropic gateway) wants
                # ANTHROPIC_AUTH_TOKEN → `Authorization: Bearer <key>`;
                # the default "api_key" (DeepSeek/Ollama) wants
                # ANTHROPIC_API_KEY → `x-api-key`. Either way we set one
                # and clear the other so an inherited Max-sub token (or a
                # stray key) can't shadow the per-agent credential.
                if endpoint_cfg.get("auth_style") == "bearer":
                    sub_env["ANTHROPIC_AUTH_TOKEN"] = api_key
                    sub_env.pop("ANTHROPIC_API_KEY", None)
                else:
                    sub_env["ANTHROPIC_API_KEY"] = api_key
                    sub_env.pop("ANTHROPIC_AUTH_TOKEN", None)
            opt_kwargs["env"] = sub_env
            # Pass --bare unless the agent explicitly opts out. Without
            # --bare the subprocess spends its startup contacting
            # Anthropic-side services (MCP proxy, keychain refresh, etc.)
            # and never gets to the actual model call when the endpoint
            # is a third-party proxy.
            if endpoint_cfg.get("bare", True):
                extra = dict(opt_kwargs.get("extra_args") or {})
                extra.setdefault("bare", None)
                opt_kwargs["extra_args"] = extra
            # Extended thinking is on by default for Sonnet/Opus. When the
            # request goes through a LiteLLM/Ollama proxy in front of a local
            # model, the proxy can't emit thinking blocks — the CLI's stream
            # parser then aborts with "Content block is not a thinking block"
            # and falls back to non-streaming, which usually times out.
            # Disable thinking by default on endpoint-overridden agents
            # unless the agent opts back in via `endpoint.thinking`. For
            # MiniMax models the block is derived from the effective model +
            # effort (M3 → adaptive/off; M2.x → always-on enabled with an
            # effort-scaled budget) so a runtime model swap stays correct —
            # see resolve_endpoint_thinking / salient/minimax.py.
            opt_kwargs.setdefault(
                "thinking",
                resolve_endpoint_thinking(endpoint_cfg, effort, model),
            )
        if stderr_callback is not None:
            # Setting `stderr=` opts the SDK into piping subprocess
            # stderr through to us (see
            # claude_agent_sdk/_internal/transport/subprocess_cli.py
            # — stderr_dest = PIPE if options.stderr is not None
            # else None). Without this, stderr inherits the daemon's
            # FD and we can't tee it for the death-classification
            # diagnostic path.
            opt_kwargs["stderr"] = stderr_callback
        return ClaudeAgentOptions(**opt_kwargs)

    def _augment_system_prompt(self, cfg: dict[str, Any]) -> str:
        # `inherit_system_prompt_from: <other-agent>` makes this agent's
        # contract = (other agent's system_prompt) + (this agent's own
        # system_prompt as overlay) + (the usual addenda + render
        # blocks below). Designed for shadow agents that want to be
        # true replicas of their primary, not hand-written restatements.
        # Fail-loud if the source isn't a known agent — silent half-
        # inheritance would render a misleading prompt the operator
        # couldn't diagnose without reading runtime telemetry.
        inherit_from = cfg.get("inherit_system_prompt_from")
        if inherit_from:
            src_cfg = self.all_cfgs.get(inherit_from)
            if src_cfg is None:
                raise ValueError(
                    f"agent {cfg.get('name')!r} declares "
                    f"`inherit_system_prompt_from: {inherit_from!r}` "
                    f"but no agent with that name exists in agents.yaml. "
                    f"Available: {sorted(self.all_cfgs)!r}"
                )
        else:
            src_cfg = None
        # Re-resolve per-agent prompt files from disk every time we bake
        # a runner, so `reset <agent>` after editing prompts/<name>.md
        # picks up the change without requiring an intermediate
        # reload_config. Skip silently when config_path isn't set
        # (sim harness / unit tests with inline system_prompt cfgs).
        config_path = getattr(self, "config_path", None)
        if config_path is not None:
            from ._prompts import resolve_per_agent_prompts

            to_refresh = [cfg]
            if src_cfg is not None:
                to_refresh.append(src_cfg)
            resolve_per_agent_prompts(to_refresh, Path(config_path).parent)
        inherited = (src_cfg.get("system_prompt") or "").strip() if src_cfg else ""
        own = (cfg.get("system_prompt") or "").strip()
        blocks: list[str] = []
        if inherited:
            blocks.append(inherited)
        if own:
            blocks.append(own)
        # Operator-curated lessons (cross-engagement). Read from
        # ~/.salient/lessons/<agent>.md (or SALIENT_LESSONS_DIR
        # override). Skipped silently when the file is missing or
        # empty — no churn for agents without lessons. Operator
        # writes via `salientctl lessons add`; the LLM never writes
        # back, by construction. See docs/LESSONS.md.
        from ..memory.lessons import read as _lessons_read

        lessons_body = _lessons_read(cfg["name"]).strip()
        if lessons_body:
            blocks.append(
                "## Operator-curated lessons (cross-engagement)\n\n"
                "These are notes the operator has accumulated from "
                "prior engagements. Treat as advisory inputs, NOT "
                "as hard rules — environment shape may have changed.\n\n" + lessons_body
            )
        tools_block = _format_tools_block(cfg)
        if tools_block:
            blocks.append(tools_block)
        approval_block = _format_approval_block(cfg.get("policy") or {})
        if approval_block:
            blocks.append(approval_block)
        engagement_block = render_profile_block(self.profile, cfg["name"])
        if engagement_block:
            blocks.append(engagement_block)
        # Endpoint-overridden agents (local LLM via LiteLLM/Ollama, third-
        # party Anthropic-compatible APIs like DeepSeek, etc.) skip the
        # 24 KB of standard agent_protocol + recipe-discipline boilerplate
        # by default. Small local models slow down dramatically on big
        # system prompts and the boilerplate's tooling discipline
        # doesn't apply to a chat-only integration-test surface. The agent's
        # own `system_prompt:` field is authoritative for these.
        #
        # Bigger third-party models (DeepSeek v4 pro, etc.) doing real
        # work CAN handle the full prompt and benefit from the discipline
        # rules. Opt back in per-agent with:
        #   endpoint:
        #     base_url: ...
        #     full_prompt: true
        endpoint_for_prompt = cfg.get("endpoint") or {}
        if (not endpoint_for_prompt) or endpoint_for_prompt.get("full_prompt"):
            blocks.append(_load_agent_protocol().rstrip())
            blocks.append(_load_recipe_discipline().rstrip())
        # Shadow agents (those with `substitute_for:`) get an extra discipline
        # block that nudges them away from over-probing on pure-methodology
        # questions and reminds them to read tool schemas before guessing.
        if cfg.get("substitute_for"):
            blocks.append(_load_shadow_discipline().rstrip())
        assembled = "\n\n".join(blocks)
        # Apply the always-on name-alias layer to the system prompt too.
        # The user-prompt path already aliases in daemon._process; the
        # system prompt is set once at agent creation and seen by Claude
        # on every turn, so leaving it unaliased would defeat the point.
        # Disable for a specific run with SALIENT_ALIAS_NAMES=0.
        from ..alias import rewrite_outbound as _alias_outbound

        return _alias_outbound(assembled)

    def _make_runner(self, cfg: dict[str, Any]) -> AgentRunner:
        # Stderr tee — the buffer lives on the runner so the run-loop
        # catch site can fold the tail into a death-classified
        # tool-error message. Build it BEFORE the options so the
        # callback closure can capture it; the SDK opts into stderr
        # piping the moment ClaudeAgentOptions sees a non-None
        # `stderr` callback.
        stderr_buffer: deque = deque(maxlen=200)

        def _stderr_sink(line: str) -> None:
            # SDK's _handle_stderr already splits on lines; we just
            # store the bare line with trailing newline stripped.
            stderr_buffer.append(line.rstrip("\r\n"))

        backend_factory: Callable[[], AgentBackend]
        runtime = cfg.get("runtime")
        tool_bundle = ToolBundle()
        if runtime is None:
            options = self._build_options(cfg, stderr_callback=_stderr_sink)
            backend_factory = partial(LocalClaudeBackend, options)
        elif isinstance(runtime, dict):
            provider_name = ProviderName(runtime.get("provider", ""))
            config = _json_value(runtime.get("config", {}))
            if not isinstance(config, dict):
                raise TypeError("runtime.config must be a mapping")
            if cfg.get("model") is not None and "model" not in config:
                config["model"] = _json_value(cfg["model"])
            provider = get_provider_registry().get(provider_name)
            tool_bundle = self._build_provider_tool_bundle(cfg)
            if provider_name == ProviderName("codex"):
                from ..codex import CodexProvider

                if not isinstance(provider, CodexProvider):
                    raise TypeError("registered codex provider has an incompatible implementation")
                config["agent_name"] = cfg["name"]
                # Dedicated per-agent scratch dir when no engagement is active,
                # never the daemon's launch cwd (source tree). See
                # _agent_work_dir.
                config["cwd"] = str(self._agent_work_dir(cfg["name"]))
                config["instructions"] = self._augment_system_prompt(cfg)
                if cfg.get("mcp_servers"):
                    config["mcp_servers"] = _json_value(cfg["mcp_servers"])

                def _make_codex_backend() -> AgentBackend:
                    loop = asyncio.get_running_loop()

                    def enqueue_followup(text: str) -> None:
                        future = asyncio.run_coroutine_threadsafe(
                            self.runners[cfg["name"]].steer(text), loop
                        )

                        def report_failure(completed: Any) -> None:
                            try:
                                completed.result()
                            except Exception:  # noqa: BLE001
                                log.exception(
                                    "Codex approval edit enqueue failed for %s", cfg["name"]
                                )

                        future.add_done_callback(report_failure)

                    return provider.create_backend(
                        config,
                        tool_bundle=tool_bundle,
                        approval_handler=self._make_codex_approval_handler(cfg["name"], loop),
                        followup_handler=enqueue_followup,
                    )

                backend_factory = _make_codex_backend
            elif provider_name == ProviderName("polybrain"):
                from ..polybrain import PolybrainProvider

                if not isinstance(provider, PolybrainProvider):
                    raise TypeError(
                        "registered polybrain provider has an incompatible implementation"
                    )
                config["agent_name"] = cfg["name"]
                config["cwd"] = str(self._agent_work_dir(cfg["name"]))
                config["instructions"] = self._augment_system_prompt(cfg)

                def _make_polybrain_backend() -> AgentBackend:
                    return provider.create_backend(
                        config,
                        tool_bundle=tool_bundle,
                        safeguard_hook=self._make_polybrain_safeguard_hook(cfg["name"]),
                    )

                backend_factory = _make_polybrain_backend
            else:
                backend_factory = partial(
                    provider.create_backend,
                    config,
                    tool_bundle=tool_bundle,
                )
        else:
            raise TypeError("runtime must be a mapping")
        r = AgentRunner(
            name=cfg["name"],
            cfg=cfg,
            backend_factory=backend_factory,
            tool_bundle=tool_bundle,
            prompt_timeout=float(cfg.get("prompt_timeout", self.prompt_timeout)),  # type: ignore[arg-type]
            idle_timeout=float(cfg.get("idle_timeout", self.idle_timeout)),  # type: ignore[arg-type]
            context=self.context,
            tail_buffer_size=int(cfg.get("tail_buffer_size", self.tail_buffer_size)),  # type: ignore[arg-type]
            on_job_complete=self._on_job_complete,
            stderr_buffer=stderr_buffer,
        )
        # Prompt-drift provenance: sha256 of the agent's resolved
        # prompt-file body (prompts/<name>.md), stamped onto every job
        # this runner records and snapshotted (deduped) so `prompt_diff`
        # can show what changed since the agent last ran. Covers the
        # authored prompt, NOT the engagement-varying assembled prompt.
        r._prompt_sha = hashlib.sha256(
            (cfg.get("system_prompt") or "").encode("utf-8", "replace")
        ).hexdigest()
        if self.context is not None:
            self.context.record_prompt_version(
                cfg["name"],
                r._prompt_sha,
                cfg.get("system_prompt") or "",
            )
        # Back-reference to the daemon, used by endpoint-override agents
        # whose local model emits OpenAI-style function-call JSON in
        # plain text — _dispatch_text_function_calls routes recognized
        # calls (ask_operator today) to their real handlers via
        # `daemon.add_question(...)`.
        r._daemon = cast("DaemonServices", self)
        from ..policy.registry import get_active
        from ..policy.safeguards import resolve_config

        r._policy_dataset = get_active()
        r._safeguard_config = resolve_config(cfg, self.profile)
        r._enforce_builtin_policy = bool(cfg.get("enforce_builtin_policy"))
        # Inject the daemon-wide event hub so _publish mirrors every event to
        # the global /ws/events/all stream (not just the per-agent tail).
        r._event_hub = self.event_hub
        # Stamp a per-incarnation epoch — a monotonic daemon-lifetime int — so
        # every event this runner publishes carries `(agent, epoch, seq)`. The
        # per-runner `seq` resets when a same-name runner is rebuilt; without
        # the epoch a hub-ring replay of the old incarnation would suppress a
        # live event with a colliding `(agent, seq)` from the new one. Lazily
        # counted on the daemon so the concrete (out-of-repo) daemon need not
        # declare the field; in-memory rings don't survive a daemon restart, so
        # a lifetime-monotonic int never collides.
        epoch = getattr(self, "_runner_epoch_counter", 0) + 1
        self._runner_epoch_counter = epoch
        r._epoch = epoch
        # Inject engagement path so the runner can write evidence files.
        r._engagement_path = self.engagement_path
        # Inject scope store so each task message gets a live "Active scope"
        # block prepended — agents see authorized targets on every turn
        # instead of repeatedly asking the operator.
        r._scope_store = self.scope
        # Wire loop-detection callback. Sync (called from inside the runner's
        # async _check_loop), so it just files an operator question via
        # add_question — non-blocking.
        r._on_loop_detected = self._on_loop_detected
        # Action ledger reference — every tool call records a row, every
        # tool result fills in the outcome. Drives prompt injection and
        # the `prior_actions` bus tool. See salient/actions.py.
        r._action_ledger = self.actions
        # Hydrate the most-recent jobs from the persistent store so the
        # operator's `info <agent>` view (and any future audit) keeps
        # context across daemon restarts. _next_job_id advances past the
        # highest persisted id to avoid collisions with new jobs.
        if self.context is not None:
            rows = self.context.load_recent_jobs(cfg["name"], limit=100)
            highest = 0
            for row in rows:
                jid = int(row["job_id"])
                if jid > highest:
                    highest = jid
                r.history.append(
                    Job(
                        id=jid,
                        prompt=row["prompt"],
                        submitted_at=row["submitted_at"],
                        started_at=row["started_at"],
                        finished_at=row["finished_at"],
                        result=row["result"],
                        error=row["error"],
                    )
                )
            # history was loaded newest-first by SQL ORDER BY DESC; flip
            # so the in-memory list reads oldest→newest like a fresh runner.
            r.history.reverse()
            # Seed the lifetime job counter from what we hydrated so the
            # `completed=` display stays accurate once history starts trimming.
            r.jobs_recorded = len(r.history)
            r._next_job_id = max(r._next_job_id, highest + 1)
        return r

    def _make_codex_approval_handler(
        self,
        agent_name: str,
        loop: asyncio.AbstractEventLoop,
    ) -> Callable[[Any], Any]:
        from ..codex import ApprovalDecision

        def handle(request: Any) -> Any:
            future = asyncio.run_coroutine_threadsafe(
                self._resolve_codex_approval(agent_name, request), loop
            )
            while not request.cancelled.wait(0.1):
                try:
                    return future.result(timeout=0)
                except TimeoutError:
                    continue
            future.cancel()
            return ApprovalDecision.CANCEL

        return handle

    async def _resolve_codex_approval(self, agent_name: str, request: Any) -> Any:
        from ..bus import _parse_delegation_answer
        from ..codex import ApprovalDecision, ApprovalResolution

        if request.kind.value == "command":
            command = request.params.get("command")
            raw_input = {"command": command}
            from ..policy.decision import InvocationIdentity, InvocationTransport, ToolInvocation
            from ..policy.safeguards import check_intent, resolve_config
            from ..policy.scope_evaluation import evaluate_scope

            runner = self.runners.get(agent_name)
            agent_cfg = (runner.cfg if runner else None) or {}
            allowed, _reason = check_intent(
                "bash.run",
                raw_input,
                config=resolve_config(agent_cfg, self.profile),
            )
            if not allowed:
                return ApprovalDecision.DECLINE
            if self.scope is not None:
                invocation = ToolInvocation.normalize(
                    InvocationIdentity(
                        InvocationTransport.SDK,
                        "CodexCommand",
                        "bash.run",
                        agent_name,
                    ),
                    raw_input,
                )
                scope_result = await evaluate_scope(invocation, self.scope)
                if not scope_result.allowed:
                    return ApprovalDecision.DECLINE
            if self._codex_command_is_read_only(request.params):
                return ApprovalDecision.ACCEPT
        elif request.kind.value == "file_change":
            root = Path(self.engagement_path or Path.cwd()).resolve()
            changes = request.params.get("changes")
            paths: list[str] = []
            if isinstance(changes, list):
                for item in changes:
                    if isinstance(item, dict):
                        changed_path = item.get("path")
                        if isinstance(changed_path, str):
                            paths.append(changed_path)
            grant_root = request.params.get("grantRoot")
            if isinstance(grant_root, str):
                paths.append(grant_root)
            for raw_path in paths:
                path = Path(raw_path)
                resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
                if not resolved.is_relative_to(root):
                    return ApprovalDecision.DECLINE
        elif request.kind.value == "permission":
            permissions = request.params.get("permissions")
            values = permissions if isinstance(permissions, list) else [permissions]
            denied = {"danger-full-access", "full_access", "root", "sudo", "all"}
            if any(str(value).lower() in denied for value in values):
                return ApprovalDecision.DECLINE

        summary_values = [
            str(request.params.get(key))
            for key in ("command", "cwd", "reason", "permissions")
            if request.params.get(key)
        ]
        summary = " | ".join(summary_values)[:300] or request.method
        qid, answer_future = self.add_tool_approval_question(
            agent_name,
            request.kind.value,
            summary,
            [request.kind.value],
        )
        try:
            answer = await asyncio.wait_for(answer_future, timeout=600)
        except TimeoutError:
            self.inbox.expire(qid, "[timed out]")
            return ApprovalDecision.DECLINE
        verdict, payload = _parse_delegation_answer(answer)
        if verdict == "approve":
            return ApprovalDecision.ACCEPT
        if verdict == "edit" and payload:
            return ApprovalResolution(ApprovalDecision.EDIT, payload)
        return ApprovalDecision.DECLINE

    @staticmethod
    def _codex_command_is_read_only(params: Mapping[str, Any]) -> bool:
        from ..codex import codex_command_is_read_only

        return codex_command_is_read_only(params)

    def _make_polybrain_safeguard_hook(self, agent_name: str):
        """Per-tool-call safeguard gate for polybrain backends.

        The polybrain backend executes `ToolBundle` handlers directly, so the
        **scope** gate fires inside the handler wrapper (scope.gate) — but the
        Claude-side **safeguards** (prohibited-intent patterns) and
        **approve_before** wire enforcement are Claude-SDK PreToolUse hooks
        that never run on this path. This hook closes that floor: it runs
        before EVERY handler invocation, and a denial means the handler is
        never called (the model gets an error tool result instead).

        Layer 1 mirrors `_make_safeguard_hook`'s intent check; layer 2 mirrors
        `_make_approve_before_hook`'s classification + operator question
        (simplified: approve/deny only — no edit verdicts in v1). Unlike the
        codex resolver, no `evaluate_scope` here: the bundle handlers already
        carry scope.gate.
        """

        async def guard(tool_name: str, arguments: Mapping[str, Any]) -> str | None:
            from ..policy.safeguards import check_intent, resolve_config

            runner = self.runners.get(agent_name)
            agent_cfg = (runner.cfg if runner else None) or {}
            allowed, reason = check_intent(
                tool_name,
                dict(arguments),
                config=resolve_config(agent_cfg, self.profile),
            )
            if not allowed:
                return reason or "prohibited by safeguards"

            gated = set((agent_cfg.get("policy") or {}).get("approve_before") or [])
            if gated:
                classify = get_daemon_skin_module("action_class").classify_tool_action
                tool_type = (agent_cfg.get("tool") or {}).get("type")
                hit = gated & classify(tool_type, tool_name, dict(arguments))
                if hit:
                    from ..bus import _parse_delegation_answer

                    args_summary = json.dumps(dict(arguments), default=str)[:200]
                    summary = f"{tool_name}({args_summary}) — classes: {', '.join(sorted(hit))}"[
                        :300
                    ]
                    qid, answer_future = self.add_tool_approval_question(
                        agent_name,
                        "polybrain_tool",
                        summary,
                        sorted(hit),
                    )
                    try:
                        answer = await asyncio.wait_for(answer_future, timeout=600)
                    except TimeoutError:
                        self.inbox.expire(qid, "[timed out]")
                        return "operator approval timed out (deny-by-default)"
                    except BaseException:
                        # Interrupt/cancel (killswitch) or any error while waiting:
                        # don't leave a phantom approval question dangling in the
                        # operator inbox for a call that will never run.
                        self.inbox.expire(qid, "[interrupted]")
                        raise
                    verdict, _payload = _parse_delegation_answer(answer)
                    if verdict != "approve":
                        return f"operator denied ({verdict or 'no'})"
            return None

        return guard

    def _build_provider_tool_bundle(self, cfg: dict[str, Any]) -> ToolBundle:
        bus_bundle, bus_wires = make_bus_tool_bundle(cast("DaemonServices", self), cfg["name"])
        tool_cfg = cfg.get("tool")
        if not isinstance(tool_cfg, dict):
            return bus_bundle
        factory_config = dict(tool_cfg.get("config") or {})
        if self.engagement_path is not None:
            factory_config.setdefault("_engagement_path", str(self.engagement_path))
        factory_config.setdefault("_listener_registry", getattr(self, "listeners", None))
        from ..policy.safeguards import posture_from_profile

        factory_config.setdefault("_posture", posture_from_profile(self.profile))
        launch = cfg.get("launch")
        if launch:
            factory_config.setdefault("_launch_profile", launch)
        browser_cfg = (self.profile or {}).get("browser") or {}
        factory_config.setdefault(
            "_authed_sessions",
            bool(browser_cfg.get("authed_sessions")),
        )
        if self.scope is not None:
            factory_config.setdefault(
                "_scope_networks",
                [
                    rule.pattern
                    for rule in self.scope.rules()
                    if rule.direction == "in" and rule.kind == "network"
                ],
            )
        from ..alias import to_wire

        context = ToolBuildContext(
            server_name=to_wire(cfg["name"]),
            scope_store=self.scope,
            agent_name=cfg["name"],
            extra_tools=bus_bundle.tools,
            extra_bare_wires=bus_wires,
        )
        return get_tool_bundle_builder()(
            tool_cfg["type"],
            factory_config,
            context=context,
        )

    def _on_loop_detected(
        self, runner: AgentRunner, tool_name: str, repeats: int, arg_hash: str
    ) -> None:
        """Called by AgentRunner._check_loop when the same tool+args repeats
        threshold times within window. File an <ask_operator> question so the
        operator can intervene; agent will see the operator's reply as its
        next prompt and can adjust / stop / continue."""
        question = (
            f"loop suspected — I've called `{tool_name}` {repeats}× in a row "
            f"with the same arguments (arg-hash {arg_hash}). This usually "
            f"means I'm stuck. Reply:\n"
            f"  STOP — I'll abandon this approach\n"
            f"  CONTINUE — false alarm, keep going\n"
            f"  ADJUST [direction] — try a different approach you suggest"
        )
        try:
            self.add_question(runner.name, question)
        except Exception as exc:
            # The whole point of loop detection is operator visibility —
            # if we can't file the question, at least log it once.
            key = f"loop_detected:{runner.name}"
            if key not in _LOOP_WARNED:
                _LOOP_WARNED.add(key)
                log.warning(
                    "[%s] loop detected but could not file operator question "
                    "(silencing further warnings for this agent): %r",
                    runner.name,
                    exc,
                )

    async def start_agent(self, name: str) -> None:
        """Bring up a configured agent (idempotent if already running). Raises
        ValueError if the name isn't in agents.yaml or is disabled by the
        engagement profile."""
        cfg = self.all_cfgs.get(name)
        if cfg is None:
            raise ValueError(f"no agent named {name!r} in config")
        if _is_agent_disabled(self.profile, name):
            raise ValueError(
                f"agent {name!r} is disabled in the engagement profile "
                f"(disabled_agents). Remove via "
                f"`salientctl prefs del disabled_agents` or edit the profile."
            )
        # One shadow per primary. Two live shadows of the same primary (e.g.
        # deepseek_msf + minimax_msf) make bus substitute-routing — which is
        # first-match-wins — ambiguous, silently stranding the loser. Refuse
        # the second. Swarm forks are exempt (they drop substitute_for);
        # switching tiers = stop one, start the other.
        primary = (cfg or {}).get("substitute_for")
        if primary:
            sibling = first_running_sibling_shadow(self.runners, name, primary)
            if sibling:
                raise ValueError(
                    f"cannot start {name!r}: {sibling!r} is already running and "
                    f"both substitute for {primary!r}. Bus substitute-routing is "
                    f"first-match-wins, so two live shadows of one primary make "
                    f"routing ambiguous. Stop the other first: "
                    f"`salientctl stop {sibling}`."
                )
        existing = self.runners.get(name)
        if existing is not None and existing.status not in ("stopped",):
            return
        try:
            runner = self._make_runner(cfg)
            self.runners[name] = runner
            await runner.start()
            self._notify_agent_spawn(name, cfg, runner)
        except Exception as e:
            log.exception("agent %s start failed: %r", name, e)
            raise
        log.info("agent %s started", name)

    @staticmethod
    def _auto_checkpoint_config() -> tuple[int, bool]:
        """Resolve auto-checkpoint config from env:
            SALIENT_AUTO_CHECKPOINT_TOKENS  — threshold (0 = disabled)
            SALIENT_AUTO_CHECKPOINT_ENABLED — '1' = auto-fire, '0' = warn only

        Returns (threshold, auto_fire). threshold=0 means disabled.
        """
        try:
            threshold = int(os.environ.get("SALIENT_AUTO_CHECKPOINT_TOKENS", "") or 0)
        except (TypeError, ValueError):
            threshold = 0
        auto_fire = os.environ.get("SALIENT_AUTO_CHECKPOINT_ENABLED", "").lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        return max(0, threshold), auto_fire

    def _check_auto_checkpoint(self, runner: AgentRunner) -> None:
        """If runner has accumulated more than the configured threshold of
        prompt tokens since its last checkpoint, log a warning and
        (when SALIENT_AUTO_CHECKPOINT_ENABLED=1) schedule an auto
        _cmd_checkpoint(name, reset=True) for it. Always resets the
        accumulator after a warning so we don't spam."""
        threshold, auto_fire = self._auto_checkpoint_config()
        if threshold <= 0:
            return  # disabled
        if getattr(runner, "_reflecting", False):
            return  # a checkpoint reflection is in flight — don't recurse
        accumulated = runner._tokens_since_checkpoint
        if accumulated < threshold:
            return
        # Reset NOW so subsequent jobs don't re-fire the warning while a
        # checkpoint task is in flight.
        runner._tokens_since_checkpoint = 0
        mode = "auto-fire" if auto_fire else "warn only"
        try:
            spawn_background(
                runner._log(
                    "auto-checkpoint",
                    f"⚠ {runner.name} accumulated {accumulated:,} prompt tokens "
                    f"since last checkpoint (threshold {threshold:,}). "
                    f"Mode: {mode}. "
                    f"Use `salientctl checkpoint {runner.name} --reset` to "
                    f"summarize-and-reset manually.",
                ),
                name=f"checkpoint-warn[{runner.name}]",
            )
        except Exception:  # noqa: BLE001
            pass
        if auto_fire:
            # Schedule the checkpoint as a background task. We can't await
            # it here — _on_job_complete is synchronous and runs inline
            # with the runner loop. The checkpoint task will queue a
            # summarize prompt onto runner.queue ahead of any new operator
            # prompts (the cmd handles its own resetting).
            try:
                spawn_background(
                    self._cmd_checkpoint({"name": runner.name, "reset": True}),
                    name=f"checkpoint[{runner.name}]",
                )
            except Exception:  # noqa: BLE001
                pass

    def _swarm_should_defer_teardown(
        self,
        orch_name: str,
        entry: dict[str, Any],
        job_result: str | None,
        job_error: str | None = None,
    ) -> bool:
        """True when an ephemeral swarm must NOT be auto-torn-down yet
        because it still owes the operator an answer.

        Tearing the swarm down here would `stop(kill=True)` + pop the
        orchestrator/members while a clarifying question is still pending,
        orphaning it: the operator's later answer hits ``agent ... no
        longer running`` in _cmd_questions_answer and the swarm never fans
        out. Keeping it alive lets the answer re-dispatch the orchestrator;
        teardown then fires on the next completed job that leaves nothing
        outstanding. (If the operator never answers, the swarm idles alive
        rather than vanishing — an explicit `kill` / `questions clear`
        forces it down, which is the right trade.)

        Covers BOTH question paths: an already-filed operator/delegation
        question on the orchestrator or any member (inbox.pending_for), and
        ``<ask_operator>`` markers in THIS reply that are about to be filed
        a few lines below — so the decision is correct even though the
        marker question is filed *after* this teardown check."""
        members = entry.get("members") or []
        for name in (orch_name, *members):
            if self.inbox.pending_for(name):
                return True
        # Markers are only FILED below when the job didn't error (see the
        # `if job.error is not None ...: return` guard in _on_job_complete).
        # Mirror that condition here: an errored job whose partial reply
        # happens to contain a marker must NOT defer — the question would
        # never be filed, stranding the swarm deferred-alive with nothing
        # to answer.
        if job_error is None and job_result and _extract_marker_questions(job_result):
            return True
        return False

    def _on_job_complete(self, runner: AgentRunner, job: Job) -> None:
        try:
            # Auto-checkpoint trigger: check threshold after every job.
            # Disabled by default — set SALIENT_AUTO_CHECKPOINT_TOKENS to
            # enable warnings, plus SALIENT_AUTO_CHECKPOINT_ENABLED=1 to
            # also fire the checkpoint automatically.
            self._check_auto_checkpoint(runner)
            # Ephemeral SWARM teardown trigger. When a job completes on
            # an orchestrator that owns an ephemeral swarm, schedule
            # _swarm_teardown — which persists synthesis + findings and
            # cascade-prunes the whole group. Fires whether the job
            # errored or not so the operator never ends up with a stuck
            # swarm waiting for a follow-up — UNLESS the swarm still owes
            # the operator an answer (a pending clarifying question, e.g.
            # an orchestrator asking before fan-out). Tearing down then
            # would orphan the question and the answer could never reach
            # the agent; defer so the swarm stays alive to receive it.
            swarms = getattr(self, "_swarms", {}) or {}
            entry = swarms.get(runner.name)
            if (
                entry
                and entry.get("ephemeral")
                and not self._swarm_should_defer_teardown(runner.name, entry, job.result, job.error)
            ):
                # Inline schedule; _on_job_complete is sync. The
                # teardown coroutine handles its own errors so a
                # broken disk write can't take the agent loop down.
                spawn_background(
                    self._swarm_teardown(
                        runner.name,
                        reason=f"ephemeral job_complete (job #{job.id})",
                    ),
                    name=f"swarm-teardown[{runner.name}]",
                )
            if job.error is not None or not job.result:
                return
            # Path 1: `ask_operator` MCP tool was already called and filed
            # the question via add_question(); nothing else to do.
            #
            # tool_question_ids may also contain DELEGATION qids when the
            # agent's ask_agent call hit a gate this turn — those are NOT
            # operator clarifying questions and shouldn't suppress marker
            # extraction. Only skip when at least one operator-kind qid
            # is present.
            if job.tool_question_ids and any(
                (q := self.inbox.get(qid)) is not None and q.kind == "operator"
                for qid in job.tool_question_ids
            ):
                return
            # Path 2: agent embedded one or more <ask_operator>...</ask_operator>
            # markers in its reply. Each marker is its own question; strip the
            # tags from the stored result. These two paths are the ENTIRE
            # protocol — no heuristics. If a reply isn't tagged, it's plain
            # reply text, full stop.
            marker_qs = _extract_marker_questions(job.result)
            if marker_qs:
                for q_text in marker_qs:
                    self._file_question(runner.name, job.id, q_text, source="marker")
                job.result = _strip_question_markers(job.result)
        finally:
            # Surface a banner to any REPL subscribed to replies_tail.
            self._publish_reply_event(runner, job)

    async def _restart_one_agent(self, name: str) -> bool:
        """Stop and re-create a single runner so it picks up new config /
        engagement state. No-op if the agent isn't currently running.
        Returns True if the agent was restarted, False if it wasn't running."""
        r = self.runners.get(name)
        if r is None or r.status == "stopped":
            return False
        await self._notify_agent_despawn(name)
        await r.stop(kill=False)
        await _drain_for_restart(r)  # let the old teardown finish before restart
        cfg = self.all_cfgs.get(name) or r.cfg
        new_runner = self._make_runner(cfg)
        self.runners[name] = new_runner
        await new_runner.start()
        self._notify_agent_spawn(name, cfg, new_runner)
        return True

    async def _restart_running_agents(self) -> list[str]:
        """Stop and re-create every currently-running runner so the new
        engagement profile gets baked into the system prompt. Stopped
        runners are left alone — they'll pick up the new profile next
        time they're started."""
        names = [n for n, r in self.runners.items() if r.status != "stopped"]
        for name in names:
            r = self.runners[name]
            await self._notify_agent_despawn(name)
            await r.stop(kill=False)
            await _drain_for_restart(r)  # let old teardown finish before restart
            cfg = self.all_cfgs.get(name) or r.cfg
            new_runner = self._make_runner(cfg)
            self.runners[name] = new_runner
            await new_runner.start()
            self._notify_agent_spawn(name, cfg, new_runner)
        return names
