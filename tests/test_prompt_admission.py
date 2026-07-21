from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from salient_core.daemon import AgentRunner
from salient_core.daemon._runner_factory import _RunnerFactoryMixin
from salient_core.policy import registry
from salient_core.policy.registry import PolicyDataset
from salient_core.policy.safeguards import (
    OperatorPromptMode,
    OperatorPromptModeError,
    SafeguardConfig,
    resolve_config,
)
from salient_core.runtime import (
    AgentEvent,
    AssistantEvent,
    TextContent,
    TurnCompletedEvent,
    TurnUsage,
)


def _dataset() -> PolicyDataset:
    return PolicyDataset(
        tool_targets={},
        prohibited_patterns={},
        loud_patterns={},
        natural_language_prohibited=(("blocked-intent", r"forbidden request"),),
    )


@pytest.fixture(autouse=True)
def _active_policy() -> None:
    registry.set_active(_dataset())
    yield
    registry.reset()


@pytest.mark.parametrize(
    ("profile", "agent", "expected"),
    [
        ({}, {}, OperatorPromptMode.LOG),
        ({"safeguards": {"refuse_operator_prompts": True}}, {}, OperatorPromptMode.SOFT_REFUSE),
        (
            {"safeguards": {"refuse_operator_prompts": True}},
            {"safeguards": {"operator_prompt_mode": "hard_refuse"}},
            OperatorPromptMode.HARD_REFUSE,
        ),
        (
            {"safeguards": {"operator_prompt_mode": "hard_refuse"}},
            {"safeguards": {"operator_prompt_mode": "log"}},
            OperatorPromptMode.LOG,
        ),
        (
            {"safeguards": {"refuse_operator_prompts": True}},
            {"safeguards": {"refuse_operator_prompts": False}},
            OperatorPromptMode.LOG,
        ),
        (
            {
                "safeguards": {
                    "operator_prompt_mode": "hard_refuse",
                    "refuse_operator_prompts": False,
                }
            },
            {},
            OperatorPromptMode.HARD_REFUSE,
        ),
    ],
)
def test_operator_prompt_mode_resolves_precedence(
    profile: dict[str, object],
    agent: dict[str, object],
    expected: OperatorPromptMode,
) -> None:
    # Given: distinct profile, legacy-alias, and agent mode inputs.
    # When: safeguard configuration is resolved at the config boundary.
    config = resolve_config(agent, profile)
    # Then: explicit agent mode wins and the default remains log-only.
    assert config.operator_prompt_mode is expected


def test_operator_prompt_mode_rejects_unknown_value() -> None:
    # Given: an invalid public mode value.
    profile = {"safeguards": {"operator_prompt_mode": "observe"}}
    # When/Then: config resolution fails closed rather than silently logging.
    with pytest.raises(OperatorPromptModeError, match="operator_prompt_mode"):
        resolve_config(None, profile)


def test_prompt_hard_limit_defaults_and_reset_state() -> None:
    # Given/When: safeguard config and a freshly recreated runner.
    previous = AgentRunner(name="guarded", cfg={})
    previous.total_prompt_hard_blocks = 3
    recreated = AgentRunner(name="guarded", cfg={})

    # Then: the threshold is three and runner recreation clears hard state.
    assert SafeguardConfig().halt_threshold == 3
    assert recreated.total_prompt_hard_blocks == 0


class _Backend:
    def __init__(self) -> None:
        self.queries: list[str] = []

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None

    async def query(self, prompt: str) -> None:
        self.queries.append(prompt)

    async def receive_response(self) -> AsyncIterator[AgentEvent]:
        yield AssistantEvent(content=(TextContent("complete"),), model="fake")
        yield TurnCompletedEvent(
            turns=1,
            duration_ms=1,
            usage=TurnUsage(input_tokens=1, output_tokens=1, cost_usd=None),
        )

    async def interrupt(self) -> None:
        return None

    async def get_context_usage(self) -> None:
        return None

    def diagnose_failure(
        self,
        agent_name: str,
        error: BaseException,
        stderr_tail: tuple[str, ...],
    ) -> str:
        del stderr_tail
        return f"{agent_name}: {error}"


@pytest.mark.anyio
async def test_hard_refuse_terminates_job_without_backend_query(tmp_path: Path) -> None:
    # Given: a live runner in hard-refuse mode and an awaiting delegated caller.
    backend = _Backend()
    runner = AgentRunner(
        name="guarded",
        cfg={"safeguards": {"operator_prompt_mode": "hard_refuse"}},
        backend_factory=lambda: backend,
        idle_timeout=0.0,
    )
    runner._safeguard_config = resolve_config(runner.cfg, None)
    runner._engagement_path = tmp_path
    await runner.start()
    future = asyncio.get_running_loop().create_future()

    # When: the prohibited job reaches the shared runner entry boundary.
    job = runner.submit("forbidden request", future=future)
    completed = await asyncio.wait_for(future, timeout=1)

    # Then: it is terminal, observable once, and never reaches the backend.
    assert completed is job
    assert job.error == "operator prompt blocked by safeguard: blocked-intent"
    assert backend.queries == []
    assert runner.total_safeguard_blocks == 1
    events = [event for event in runner.recent_events if event["kind"] == "safeguard_prompt_block"]
    assert len(events) == 1
    assert events[0]["meta"] == {
        "agent": "guarded",
        "job_id": job.id,
        "reason": "blocked-intent",
        "mode": "hard_refuse",
        "count": 1,
        "halt_at": 3,
    }
    assert "forbidden request" not in str(events[0])
    await runner.stop()
    assert runner._task is not None
    await runner._task
    records = [
        json.loads(line) for line in (tmp_path / "logs" / "guarded.jsonl").read_text().splitlines()
    ]
    blocks = [record for record in records if record["kind"] == "safeguard_prompt_block"]
    assert len(blocks) == 1
    assert blocks[0]["content"] == events[0]["meta"]
    assert "forbidden request" not in str(blocks[0])


@pytest.mark.anyio
async def test_hard_refuse_allows_benign_job_unchanged() -> None:
    # Given: the same hard-refuse boundary with a benign internal submission.
    backend = _Backend()
    runner = AgentRunner(
        name="guarded",
        cfg={"safeguards": {"operator_prompt_mode": "hard_refuse"}},
        backend_factory=lambda: backend,
        idle_timeout=0.0,
    )
    runner._safeguard_config = resolve_config(runner.cfg, None)
    await runner.start()
    future = asyncio.get_running_loop().create_future()

    # When: the benign job reaches the shared boundary.
    job = runner.submit("benign request", future=future)
    await asyncio.wait_for(future, timeout=1)

    # Then: the raw task reaches the backend and consumes no safeguard strike.
    assert backend.queries == ["benign request"]
    assert job.error is None
    assert runner.total_safeguard_blocks == 0
    await runner.stop()
    assert runner._task is not None
    await runner._task


@pytest.mark.anyio
async def test_live_profile_changes_gate_in_both_directions() -> None:
    # Given: one live runner whose daemon profile begins in log mode.
    backend = _Backend()
    runner = AgentRunner(name="live", cfg={}, backend_factory=lambda: backend, idle_timeout=0.0)
    daemon = type("Daemon", (), {"profile": {"safeguards": {"operator_prompt_mode": "log"}}})()
    runner._daemon = daemon
    await runner.start()

    async def submit(prompt: str):
        future = asyncio.get_running_loop().create_future()
        job = runner.submit(prompt, future=future)
        await asyncio.wait_for(future, timeout=1)
        return job

    # When: the same profile flips log -> hard -> log between jobs.
    first = await submit("forbidden request")
    daemon.profile = {"safeguards": {"operator_prompt_mode": "hard_refuse"}}
    blocked = await submit("forbidden request")
    daemon.profile = {"safeguards": {"operator_prompt_mode": "log"}}
    final = await submit("forbidden request")

    # Then: each job obeys the mode current at its own admission boundary.
    assert first.error is None
    assert blocked.error == "operator prompt blocked by safeguard: blocked-intent"
    assert final.error is None
    assert backend.queries == ["forbidden request", "forbidden request"]
    await runner.stop()
    assert runner._task is not None
    await runner._task


@pytest.mark.anyio
async def test_sticky_prompt_halt_blocks_benign_without_increment() -> None:
    # Given: a hard-refuse runner whose shared safeguard budget is exhausted.
    backend = _Backend()
    runner = AgentRunner(
        name="halted",
        cfg={"safeguards": {"operator_prompt_mode": "hard_refuse", "halt_threshold": 2}},
        backend_factory=lambda: backend,
        idle_timeout=0.0,
    )
    runner.total_safeguard_blocks = 2
    runner.total_prompt_hard_blocks = 2
    await runner.start()
    future = asyncio.get_running_loop().create_future()

    # When: a benign job reaches prompt admission before reset.
    job = runner.submit("benign request", future=future)
    await asyncio.wait_for(future, timeout=1)

    # Then: sticky halt is distinct, honest, and does not consume another strike.
    assert job.error == "runner halted after 2/2 safeguard blocks; reset required"
    assert backend.queries == []
    assert runner.total_safeguard_blocks == 2
    halts = [event for event in runner.recent_events if event["kind"] == "safeguard_prompt_halt"]
    assert len(halts) == 1
    assert halts[0]["meta"]["reason"] == "halt_threshold_reached"
    await runner.stop()
    assert runner._task is not None
    await runner._task


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["log", "soft_refuse"])
async def test_non_hard_mode_does_not_apply_prompt_halt(mode: str) -> None:
    # Given: a compatibility mode runner whose shared tool safeguard count is exhausted.
    backend = _Backend()
    runner = AgentRunner(
        name="compatible",
        cfg={"safeguards": {"operator_prompt_mode": mode, "halt_threshold": 2}},
        backend_factory=lambda: backend,
        idle_timeout=0.0,
    )
    runner.total_safeguard_blocks = 2
    await runner.start()
    future = asyncio.get_running_loop().create_future()

    # When: a benign prompt reaches admission in log or soft-refuse mode.
    job = runner.submit("benign request", future=future)
    await asyncio.wait_for(future, timeout=1)

    # Then: compatibility mode still dispatches and leaves the shared count unchanged.
    assert job.error is None
    assert backend.queries == ["benign request"]
    assert runner.total_safeguard_blocks == 2
    await runner.stop()
    assert runner._task is not None
    await runner._task


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["log", "soft_refuse"])
async def test_observed_matches_do_not_arm_later_hard_halt(mode: str) -> None:
    # Given: three compatibility-mode observations with no hard enforcement.
    backend = _Backend()
    runner = AgentRunner(name="live", cfg={}, backend_factory=lambda: backend, idle_timeout=0.0)
    daemon = _HookDaemon(runner)
    runner._daemon = daemon
    daemon.profile = {"safeguards": {"operator_prompt_mode": mode}}
    hook = daemon._make_prompt_safeguard_hook("guarded")
    for index in range(3):
        await hook({"prompt": "forbidden request"}, str(index), None)

    # When: the profile switches to hard and a benign job is admitted.
    daemon.profile = {"safeguards": {"operator_prompt_mode": "hard_refuse"}}
    await runner.start()
    future = asyncio.get_running_loop().create_future()
    job = runner.submit("benign request", future=future)
    await asyncio.wait_for(future, timeout=1)

    # Then: observations remain visible but do not arm the hard halt.
    assert runner.total_safeguard_blocks == 3
    assert runner.total_prompt_hard_blocks == 0
    assert job.error is None
    assert backend.queries == ["benign request"]
    await runner.stop()
    assert runner._task is not None
    await runner._task


class _HookRunner:
    def __init__(self, mode: str) -> None:
        self.cfg = {"safeguards": {"operator_prompt_mode": mode}}
        self.total_safeguard_blocks = 0
        self.total_prompt_hard_blocks = 0
        self.records: list[tuple[str, dict[str, object]]] = []
        self.events: list[tuple[str, dict[str, object]]] = []

    async def _record_jsonl(self, event: str, payload: dict[str, object]) -> None:
        self.records.append((event, payload))

    def _publish(
        self,
        event: str,
        text: str,
        *,
        meta: dict[str, object],
    ) -> None:
        del text
        self.events.append((event, meta))


class _HookDaemon(_RunnerFactoryMixin):
    def __init__(self, runner: _HookRunner) -> None:
        self.runners = {"guarded": runner}
        self.profile: dict[str, object] = {}


@pytest.mark.anyio
async def test_prompt_hook_uses_same_live_profile_resolver() -> None:
    # Given: a real runner shared with the hook daemon in log mode.
    runner = AgentRunner(name="guarded", cfg={})
    daemon = _HookDaemon(runner)
    runner._daemon = daemon
    hook = daemon._make_prompt_safeguard_hook("guarded")

    # When: the profile flips log -> hard -> soft around hook evaluations.
    logged = await hook({"prompt": "forbidden request"}, "one", None)
    daemon.profile = {"safeguards": {"operator_prompt_mode": "hard_refuse"}}
    hard = await hook({"prompt": "forbidden request"}, "two", None)
    daemon.profile = {"safeguards": {"operator_prompt_mode": "soft_refuse"}}
    soft = await hook({"prompt": "forbidden request"}, "three", None)

    # Then: hard fallback audits once while surrounding modes retain their contracts.
    assert logged == {}
    assert hard["decision"] == "block"
    assert bool(soft["hookSpecificOutput"]["additionalContext"])
    assert runner.total_safeguard_blocks == 3


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("mode", "has_context", "blocked"),
    [("log", False, False), ("soft_refuse", True, False), ("hard_refuse", False, True)],
)
async def test_prompt_hook_preserves_log_and_soft_without_hard_double_count(
    mode: str,
    has_context: bool,
    blocked: bool,
) -> None:
    # Given: each prompt-admission mode at the SDK hook boundary.
    runner = _HookRunner(mode)
    hook = _HookDaemon(runner)._make_prompt_safeguard_hook("guarded")

    # When: the SDK presents a prohibited prompt.
    result = await hook({"prompt": "forbidden request"}, "id", None)

    # Then: log/soft retain their behavior while hard mode is already handled upstream.
    assert bool(result.get("hookSpecificOutput", {}).get("additionalContext")) is has_context
    assert (result.get("decision") == "block") is blocked
    assert runner.total_safeguard_blocks == 1
    assert len(runner.records) == 1


@pytest.mark.anyio
async def test_hard_hook_fallback_allows_benign_prompt_unchanged() -> None:
    # Given: hard mode at the SDK hook after runner admission.
    runner = _HookRunner("hard_refuse")
    hook = _HookDaemon(runner)._make_prompt_safeguard_hook("guarded")

    # When: the admitted prompt is benign.
    result = await hook({"prompt": "benign request"}, "id", None)

    # Then: the fallback does not alter it or consume safeguard evidence.
    assert result == {}
    assert runner.total_safeguard_blocks == 0
    assert runner.records == []


@pytest.mark.anyio
async def test_hard_hook_fallback_uses_runner_pinned_dataset() -> None:
    # Given: a hard runner whose pinned dataset differs from the active registry.
    pinned = PolicyDataset(
        tool_targets={},
        prohibited_patterns={},
        loud_patterns={},
        natural_language_prohibited=(("pinned", r"pinned-only"),),
    )
    runner = AgentRunner(
        name="guarded",
        cfg={"safeguards": {"operator_prompt_mode": "hard_refuse"}},
    )
    runner._policy_dataset = pinned
    daemon = _HookDaemon(runner)
    runner._daemon = daemon
    hook = daemon._make_prompt_safeguard_hook("guarded")

    # When: a prompt matches only the runner-pinned policy.
    result = await hook({"prompt": "pinned-only"}, "id", None)

    # Then: defense-in-depth terminal refusal uses policy parity and audits its sole match.
    assert result["decision"] == "block"
    assert runner.total_safeguard_blocks == 1


@pytest.mark.anyio
async def test_log_to_hard_hook_race_records_one_fallback_audit() -> None:
    # Given: runner admission occurred under log mode before a live hard-mode flip.
    runner = _HookRunner("log")
    runner.cfg = {}
    daemon = _HookDaemon(runner)
    daemon.profile = {"safeguards": {"operator_prompt_mode": "log"}}
    hook = daemon._make_prompt_safeguard_hook("guarded")
    daemon.profile = {"safeguards": {"operator_prompt_mode": "hard_refuse"}}

    # When: the prohibited prompt reaches the hook after the flip.
    result = await hook({"prompt": "forbidden request"}, "race", None)

    # Then: terminal block, one strike, and one durable audit describe the match.
    assert result["decision"] == "block"
    assert runner.total_safeguard_blocks == 1
    assert len(runner.records) == 1
    event, payload = runner.records[0]
    assert event == "safeguard_prompt_flag"
    assert payload["mode"] == "hard_refuse"
    assert "prompt" not in payload


@pytest.mark.anyio
async def test_hard_hook_fallback_redacts_live_and_durable_audit(tmp_path: Path) -> None:
    # Given: a hard fallback with a sentinel-bearing prohibited prompt.
    sentinel = "forbidden request CONFIDENTIAL-SENTINEL"
    runner = AgentRunner(
        name="guarded",
        cfg={"safeguards": {"operator_prompt_mode": "hard_refuse"}},
    )
    runner._engagement_path = tmp_path
    daemon = _HookDaemon(runner)
    runner._daemon = daemon
    hook = daemon._make_prompt_safeguard_hook("guarded")

    # When: the prompt reaches the defense-in-depth hook.
    result = await hook({"prompt": sentinel}, "race", None)

    # Then: one strike/audit is observable without the raw prompt in either sink.
    assert result["decision"] == "block"
    assert runner.total_safeguard_blocks == 1
    live = [event for event in runner.recent_events if event["kind"] == "safeguard_prompt_flag"]
    assert len(live) == 1
    assert "CONFIDENTIAL-SENTINEL" not in str(live[0])
    records = [
        json.loads(line) for line in (tmp_path / "logs" / "guarded.jsonl").read_text().splitlines()
    ]
    durable = [record for record in records if record["kind"] == "safeguard_prompt_flag"]
    assert len(durable) == 1
    assert "CONFIDENTIAL-SENTINEL" not in str(durable[0])


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["log", "soft_refuse"])
async def test_compatibility_hook_audit_preserves_prompt_visibility(mode: str) -> None:
    # Given: an existing compatibility-mode prompt audit.
    runner = _HookRunner(mode)
    hook = _HookDaemon(runner)._make_prompt_safeguard_hook("guarded")

    # When: a prohibited prompt matches.
    await hook({"prompt": "forbidden request visible-marker"}, "id", None)

    # Then: legacy operator-visible prompt evidence remains unchanged.
    assert runner.records[0][1]["prompt"] == "forbidden request visible-marker"


@pytest.mark.anyio
async def test_invalid_live_mode_fails_closed_without_killing_runner() -> None:
    # Given: a live runner whose profile becomes invalid after construction.
    backend = _Backend()
    runner = AgentRunner(name="invalid", cfg={}, backend_factory=lambda: backend, idle_timeout=0.0)
    daemon = type("Daemon", (), {"profile": {"safeguards": {"operator_prompt_mode": "invalid"}}})()
    runner._daemon = daemon
    await runner.start()
    future = asyncio.get_running_loop().create_future()

    # When: a job reaches admission under the invalid live mode.
    job = runner.submit("benign request", future=future)
    await asyncio.wait_for(future, timeout=1)

    # Then: it fails closed and the runner survives a corrected profile.
    assert job.error is not None and "invalid safeguard configuration" in job.error
    assert backend.queries == []
    daemon.profile = {"safeguards": {"operator_prompt_mode": "log"}}
    recovered_future = asyncio.get_running_loop().create_future()
    recovered = runner.submit("benign request", future=recovered_future)
    await asyncio.wait_for(recovered_future, timeout=1)
    assert recovered.error is None
    assert backend.queries == ["benign request"]
    await runner.stop()
    assert runner._task is not None
    await runner._task


@pytest.mark.anyio
async def test_invalid_hook_mode_and_missing_runner_block_before_model() -> None:
    # Given: one invalid live hook and one hard hook whose runner disappeared.
    runner = _HookRunner("log")
    invalid_daemon = _HookDaemon(runner)
    invalid_daemon.profile = {"safeguards": {"operator_prompt_mode": "invalid"}}
    invalid_hook = invalid_daemon._make_prompt_safeguard_hook("guarded")
    missing_daemon = _HookDaemon(runner)
    missing_daemon.runners = {}
    missing_daemon.profile = {"safeguards": {"operator_prompt_mode": "hard_refuse"}}
    missing_hook = missing_daemon._make_prompt_safeguard_hook("guarded")

    # When: both callbacks receive prompts.
    invalid = await invalid_hook({"prompt": "benign request"}, "invalid", None)
    missing = await missing_hook({"prompt": "forbidden request"}, "missing", None)

    # Then: both return the SDK's terminal pre-model block contract.
    assert invalid["decision"] == "block"
    assert missing["decision"] == "block"


@pytest.mark.anyio
async def test_removed_runner_preserves_agent_local_hard_context(tmp_path: Path) -> None:
    # Given: an agent-local hard callback captured before its runner disappears.
    sentinel = "forbidden request REMOVED-RUNNER-SENTINEL"
    runner = AgentRunner(name="guarded", cfg={})
    runner._engagement_path = tmp_path
    daemon = _HookDaemon(runner)
    daemon.profile = {"safeguards": {"operator_prompt_mode": "log"}}
    agent_cfg = {"safeguards": {"operator_prompt_mode": "hard_refuse"}}
    hook = daemon._make_prompt_safeguard_hook("guarded", agent_cfg=agent_cfg)
    agent_cfg["safeguards"]["operator_prompt_mode"] = "log"
    daemon.runners = {}

    # When: a prohibited prompt arrives after removal.
    result = await hook({"prompt": sentinel}, "removed", None)

    # Then: immutable policy blocks and the captured runner records one sanitized audit.
    assert result["decision"] == "block"
    assert runner.total_safeguard_blocks == 1
    assert runner.total_prompt_hard_blocks == 1
    live = [event for event in runner.recent_events if event["kind"] == "safeguard_prompt_flag"]
    assert len(live) == 1
    records = [
        json.loads(line) for line in (tmp_path / "logs" / "guarded.jsonl").read_text().splitlines()
    ]
    durable = [record for record in records if record["kind"] == "safeguard_prompt_flag"]
    assert len(durable) == 1
    assert "prompt" not in durable[0]["content"]
    assert "REMOVED-RUNNER-SENTINEL" not in str(live + durable)


@pytest.mark.anyio
async def test_removed_runner_preserves_pinned_policy_dataset() -> None:
    # Given: a callback whose pinned dataset is stricter than the active dataset.
    runner = _HookRunner("log")
    daemon = _HookDaemon(runner)
    daemon.profile = {"safeguards": {"operator_prompt_mode": "log"}}
    pinned = PolicyDataset(
        tool_targets={},
        prohibited_patterns={},
        loud_patterns={},
        natural_language_prohibited=(("pinned", r"pinned-after-removal"),),
    )
    hook = daemon._make_prompt_safeguard_hook(
        "guarded",
        agent_cfg={"safeguards": {"operator_prompt_mode": "hard_refuse"}},
        dataset=pinned,
    )
    daemon.runners = {}

    # When: a prompt matches only the callback's pinned dataset.
    result = await hook({"prompt": "pinned-after-removal"}, "removed", None)

    # Then: runner disappearance cannot downgrade dataset enforcement.
    assert result["decision"] == "block"


@pytest.mark.anyio
async def test_replacement_runner_is_the_only_hook_audit_sink() -> None:
    # Given: a callback captured on one runner before a same-name replacement.
    original = _HookRunner("hard_refuse")
    replacement = _HookRunner("hard_refuse")
    daemon = _HookDaemon(original)
    hook = daemon._make_prompt_safeguard_hook("guarded")
    daemon.runners["guarded"] = replacement

    # When: a prohibited prompt reaches the callback after replacement.
    result = await hook({"prompt": "forbidden request"}, "replacement", None)

    # Then: the current runner receives exactly one audit and the original receives none.
    assert result["decision"] == "block"
    assert original.total_safeguard_blocks == 0
    assert original.records == []
    assert original.events == []
    assert replacement.total_safeguard_blocks == 1
    assert replacement.total_prompt_hard_blocks == 1
    assert len(replacement.records) == 1
    assert len(replacement.events) == 1
