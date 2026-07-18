from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio

from salient_core.policy import registry, scope, scope_evaluation
from salient_core.policy.decision import (
    InvocationIdentity,
    InvocationTransport,
    ToolInvocation,
)
from salient_core.policy.registry import PolicyDataset
from salient_core.policy.scope_evaluation import ScopeEvaluationKind, evaluate_scope


def _dataset(targets: dict[str, scope.ExtractorSpec]) -> PolicyDataset:
    return PolicyDataset(tool_targets=targets, prohibited_patterns={}, loud_patterns={})


def _invocation(qualified_name: str, raw_input: dict[str, Any]) -> ToolInvocation:
    return ToolInvocation.normalize(
        InvocationIdentity(InvocationTransport.MCP, "scan", qualified_name, "scope-agent"),
        raw_input,
    )


def _evaluate(invocation: ToolInvocation, store: scope.ScopeStore, dataset: PolicyDataset):
    return anyio.run(evaluate_scope, invocation, store, dataset)


def _rows(store: scope.ScopeStore) -> list[tuple[str, str, str]]:
    assert store._conn is not None
    return list(store._conn.execute("SELECT args_json,targets_json,reason FROM scope_decisions"))


def test_evaluator_prefers_qualified_specs_and_keeps_bare_fallback() -> None:
    # Given two qualified collisions plus a compatibility-only bare entry.
    store = scope.ScopeStore(None, "qualified")
    dataset = _dataset(
        {
            "alpha.scan": scope.ExtractorSpec(fields={"alpha": "host"}),
            "beta.scan": scope.ExtractorSpec(fields={"beta": "ip_or_host"}),
            "scan": scope.ExtractorSpec(fields={"fallback": "host"}),
        }
    )

    # When each canonical identity and an unmatched identity are evaluated.
    alpha = _evaluate(
        _invocation(
            "alpha.scan",
            {"alpha": "alpha.example", "fallback": "fallback.example"},
        ),
        store,
        dataset,
    )
    beta = _evaluate(
        _invocation("beta.scan", {"beta": "192.0.2.8"}),
        store,
        dataset,
    )
    fallback = _evaluate(
        _invocation("gamma.scan", {"fallback": "fallback.example"}),
        store,
        dataset,
    )

    # Then qualified entries win, while the bare entry remains compatible.
    assert [target.value for target in alpha.targets] == ["alpha.example"]
    assert [target.value for target in beta.targets] == ["192.0.2.8"]
    assert [target.value for target in fallback.targets] == ["fallback.example"]


def test_evaluator_missing_classification_fails_closed(tmp_path: Path) -> None:
    # Given an invocation absent from the dataset.
    store = scope.ScopeStore(tmp_path / "scope.db", "missing")
    try:
        # When it is evaluated.
        result = _evaluate(
            _invocation("alpha.scan", {"target": "example.com"}), store, _dataset({})
        )

        # Then it fails closed and persists one denial.
        assert result.allowed is False
        assert result.kind is ScopeEvaluationKind.UNCLASSIFIED
        assert "no scope classification" in result.reason
        assert len(_rows(store)) == 1
    finally:
        store.close()


def test_evaluator_extracts_raw_nested_secret_but_persists_redaction(tmp_path: Path) -> None:
    # Given an extractor whose target is nested inside a secret-named field.
    def nested_secret(ctx: scope.ExtractorCtx) -> list[scope.Target]:
        payload = ctx.args[ctx.field]
        return [
            scope.Target("host", payload["password"]["host"].lower(), f"{ctx.field}.password.host"),
            scope.Target("host", payload["api_key"].lower(), "opaque-source"),
            scope.Target("host", payload["public"], f"{ctx.field}.public"),
        ]

    scope.register_extractor("nested_secret_target", nested_secret)
    store = scope.ScopeStore(tmp_path / "scope.db", "redaction")
    try:
        store.add_adhoc("allowed.example", reason="force target-specific summary")
        invocation = _invocation(
            "alpha.scan",
            {
                "payload": {
                    "password": {"host": "Password-Secret.Example", "version": 1},
                    "api_key": "Api.Key+Secret[1].Example",
                    "public": "public1.example",
                },
                "password": "user@Example.Com",
                "api_key": "user@Sub.Example.Com",
            },
        )

        # When policy extracts and denies the raw target.
        result = _evaluate(
            invocation,
            store,
            _dataset(
                {
                    "alpha.scan": scope.ExtractorSpec(
                        fields={
                            "payload": "nested_secret_target",
                            "password": "host",
                            "api_key": "host",
                        }
                    )
                }
            ),
        )

        # Then the target is correct, but durable input contains only redaction.
        rows = _rows(store)
        assert [target.value for target in result.targets] == (
            "password-secret.example,api.key+secret[1].example,public1.example,"
            "example.com,sub.example.com"
        ).split(",")
        assert len(rows) == 1
        durable_row = "".join(rows[0])
        assert "password-secret.example" not in durable_row
        assert "example.com" not in durable_row
        assert "sub.<redacted-secret>" not in durable_row
        assert "api.key+secret[1].example" not in durable_row
        assert "host secret.example" not in durable_row
        assert json.loads(rows[0][0]) == {
            "payload": {
                "password": "<redacted-secret>",
                "api_key": "<redacted-secret>",
                "public": "public1.example",
            },
            "password": "<redacted-secret>",
            "api_key": "<redacted-secret>",
        }
        assert [target["value"] for target in json.loads(rows[0][1])] == (
            ["<redacted-secret>"] * 2 + ["public1.example"] + ["<redacted-secret>"] * 2
        )
    finally:
        store.close()
        scope.unregister_all_extractors()


def test_one_evaluation_writes_at_most_one_scope_row(tmp_path: Path) -> None:
    # Given classified local, targetless, and strict invocations.
    store = scope.ScopeStore(tmp_path / "scope.db", "cardinality")
    try:
        cases = (
            ("alpha.local", scope.ExtractorSpec(local_only=True), {}),
            ("alpha.none", scope.ExtractorSpec(none=True), {}),
            (
                "alpha.strict",
                scope.ExtractorSpec(fields={"target": "host"}),
                {"target": "denied.example"},
            ),
        )

        # When each invocation is evaluated exactly once.
        row_deltas: list[int] = []
        for qualified, spec, args in cases:
            before = len(_rows(store))
            _evaluate(_invocation(qualified, args), store, _dataset({qualified: spec}))
            row_deltas.append(len(_rows(store)) - before)

        # Then no evaluation writes twice and none=True retains its no-log behavior.
        assert row_deltas == [1, 0, 1]
    finally:
        store.close()


def test_session_scope_bypasses_until_strict_mode_is_enabled() -> None:
    # Given a session-scoped extractor and legacy strict-mode default.
    store = scope.ScopeStore(None, "session")
    spec = scope.ExtractorSpec(
        fields={"command": "raw_argv"},
        session_scoped=True,
    )
    invocation = _invocation("alpha.scan", {})

    # When the invocation is evaluated before and after strict opt-in.
    bypass = _evaluate(invocation, store, _dataset({"alpha.scan": spec}))
    store.load_engagement_rules({"scope": {"session_strict": True}})
    strict = _evaluate(invocation, store, _dataset({"alpha.scan": spec}))

    # Then legacy mode bypasses and strict mode enforces extraction.
    assert (bypass.kind, bypass.allowed) == (ScopeEvaluationKind.SESSION_BYPASS, True)
    assert (strict.kind, strict.allowed) == (ScopeEvaluationKind.EXTRACTION_DENIED, False)


def test_unresolved_operator_infra_placeholder_fails_closed_before_dispatch() -> None:
    # Given a raw command whose only apparent destination is a redaction placeholder.
    store = scope.ScopeStore(None, "placeholder")
    spec = scope.ExtractorSpec(fields={"command": "raw_argv"})
    invocation = _invocation(
        "alpha.run",
        {"command": "nc <lhost> <lport>"},
    )

    # When the invocation is evaluated through the transport-neutral scope gate.
    result = _evaluate(invocation, store, _dataset({"alpha.run": spec}))

    # Then it is an extraction denial, never an allowed empty-target call.
    assert result.allowed is False
    assert result.kind is ScopeEvaluationKind.EXTRACTION_DENIED
    assert "unresolved operator-infrastructure placeholder" in result.reason


def test_research_scope_uses_public_lane_until_disabled() -> None:
    # Given a passive research target that is outside strict engagement scope.
    store = scope.ScopeStore(None, "research")
    spec = scope.ExtractorSpec(
        fields={"target": "ip_or_host"},
        research=True,
    )
    invocation = _invocation("alpha.scan", {"target": "8.8.8.8"})
    dataset = _dataset({"alpha.scan": spec})

    # When the same invocation is evaluated with research enabled and disabled.
    research = _evaluate(invocation, store, dataset)
    request = scope_evaluation.ScopeEvaluationRequest(
        dataset=dataset,
        allow_research=False,
    )
    strict = anyio.run(evaluate_scope, invocation, store, request)

    # Then only the enabled public research lane allows it.
    assert research.kind is ScopeEvaluationKind.RESEARCH
    assert research.allowed is True
    assert strict.kind is ScopeEvaluationKind.STRICT
    assert strict.allowed is False


def test_strict_evaluation_preserves_one_shot_consumption() -> None:
    # Given a one-shot rule for a classified strict target.
    store = scope.ScopeStore(None, "one-shot")
    store.add_adhoc("one.example", one_shot=True, reason="single approved call")
    dataset = _dataset({"alpha.scan": scope.ExtractorSpec(fields={"target": "host"})})
    invocation = _invocation("alpha.scan", {"target": "one.example"})

    # When the same target is evaluated twice.
    first = _evaluate(invocation, store, dataset)
    second = _evaluate(invocation, store, dataset)

    # Then the successful first call consumes the rule before the second.
    assert first.allowed is True
    assert second.allowed is False


# ── probe mode (read-only preview) — the anti-drift + purity guarantees ──────
# `evaluate_scope(mode="probe")` must return the IDENTICAL verdict as enforce
# while writing no audit row and consuming no one-shot rule. These are the
# council-mandated guardrails for the `scope gate-probe` operator command: a
# probe that could disagree with the gate, or that mutates state, is worse than
# no probe.


def _evaluate_mode(invocation, store, dataset, mode):
    return anyio.run(functools.partial(evaluate_scope, invocation, store, dataset, mode=mode))


# (dataset specs, qualified name, raw input, in-scope rule) covering every
# audit-writing / verdict-bearing branch reachable with built-in kinds.
_PROBE_MATRIX = [
    ({"a.scan": scope.ExtractorSpec(none=True)}, "a.scan", {"x": "1"}, None),
    ({"a.scan": scope.ExtractorSpec(local_only=True)}, "a.scan", {"x": "1"}, None),
    ({}, "a.scan", {"x": "1"}, None),  # unclassified → fail-closed deny
    (
        {"a.scan": scope.ExtractorSpec(fields={"target": "host"})},
        "a.scan",
        {"target": "host.example"},
        "host.example",
    ),  # strict allow
    (
        {"a.scan": scope.ExtractorSpec(fields={"target": "host"})},
        "a.scan",
        {"target": "evil.example"},
        "host.example",
    ),  # strict deny
]


def test_probe_verdict_matches_enforce_across_fixtures() -> None:
    """Anti-drift: probe returns the same `allowed` AND `kind` as enforce for
    every branch. The whole risk is a probe that says allow when the gate denies."""
    for specs, qn, raw, in_rule in _PROBE_MATRIX:
        store = scope.ScopeStore(None, "matrix")
        if in_rule:
            store.add_adhoc(in_rule, reason="in")
        dataset = _dataset(specs)
        inv = _invocation(qn, raw)
        # probe first — it must not perturb the subsequent enforce verdict.
        probe = _evaluate_mode(inv, store, dataset, "probe")
        enforce = _evaluate_mode(inv, store, dataset, "enforce")
        assert probe.allowed == enforce.allowed, (qn, raw, probe.reason, enforce.reason)
        assert probe.kind == enforce.kind, (qn, raw)


def test_probe_does_not_consume_one_shot() -> None:
    """A one-shot allow-rule survives any number of probes, and is spent only by
    the first ENFORCE call — the read-only guarantee for single-use auth."""
    store = scope.ScopeStore(None, "probe-oneshot")
    store.add_adhoc("one.example", one_shot=True, reason="single")
    dataset = _dataset({"a.scan": scope.ExtractorSpec(fields={"target": "host"})})
    inv = _invocation("a.scan", {"target": "one.example"})
    assert _evaluate_mode(inv, store, dataset, "probe").allowed is True
    assert _evaluate_mode(inv, store, dataset, "probe").allowed is True  # still live
    assert _evaluate_mode(inv, store, dataset, "enforce").allowed is True  # consumes it
    assert _evaluate_mode(inv, store, dataset, "enforce").allowed is False  # now spent
    assert _evaluate_mode(inv, store, dataset, "probe").allowed is False  # probe agrees


def test_probe_writes_no_audit_row(tmp_path: Path) -> None:
    """Probe mode is durably read-only: no scope_decisions row for any branch
    that enforce would audit (local_only / unclassified / strict allow+deny).
    Uses a file-backed store so the audit table (_conn) actually exists."""
    cases = [
        (
            {"a.scan": scope.ExtractorSpec(fields={"target": "host"})},
            "a.scan",
            {"target": "host.example"},
        ),
        (
            {"a.scan": scope.ExtractorSpec(fields={"target": "host"})},
            "a.scan",
            {"target": "evil.example"},
        ),
        ({}, "a.scan", {"x": "1"}),
        ({"a.scan": scope.ExtractorSpec(local_only=True)}, "a.scan", {"x": "1"}),
    ]
    for i, (specs, qn, raw) in enumerate(cases):
        store = scope.ScopeStore(tmp_path / f"scope{i}.db", "probe-audit")
        store.add_adhoc("host.example", reason="in")
        before = len(_rows(store))
        _evaluate_mode(_invocation(qn, raw), store, _dataset(specs), "probe")
        assert len(_rows(store)) == before, (qn, raw)
        # sanity: enforce DOES write a row for the same call.
        _evaluate_mode(_invocation(qn, raw), store, _dataset(specs), "enforce")
        assert len(_rows(store)) == before + 1, (qn, raw)


@dataclass(frozen=True)
class _Tool:
    handler: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def test_public_gate_preserves_refusal_rendering_and_source_compatibility() -> None:
    # Given the existing positional gate call and an unclassified tool.
    async def handler(args: dict[str, Any]) -> dict[str, Any]:
        return {"ok": args}

    store = scope.ScopeStore(None, "gate")
    wrapped = scope.gate(
        _Tool(handler),
        "scan",
        "scope-agent",
        store,
        "alpha",
        dataset=_dataset({}),
    )

    # When the wrapped handler is called.
    result = anyio.run(wrapped.handler, {"target": "example.com"})

    # Then the established MCP response shape and text are unchanged.
    text = (
        "REFUSED (scope): tool 'scan' has no scope classification — "
        "refusing fail-closed. Add an entry to the active "
        "PolicyDataset.tool_targets (policy.registry.set_active)."
    )
    assert result == {"content": [{"type": "text", "text": text}], "is_error": True}


def test_public_gate_is_idempotent_when_tool_is_wrapped_twice(tmp_path: Path) -> None:
    # Given a local-only tool wrapped through the public gate twice.
    calls: list[dict[str, Any]] = []

    async def handler(args: dict[str, Any]) -> dict[str, Any]:
        calls.append(args)
        return {"ok": args}

    store = scope.ScopeStore(tmp_path / "scope.db", "double-gate")
    try:
        dataset = _dataset({"alpha.scan": scope.ExtractorSpec(local_only=True)})
        once = scope.gate(_Tool(handler), "scan", "scope-agent", store, "alpha", dataset=dataset)
        twice = scope.gate(once, "scan", "scope-agent", store, "alpha", dataset=dataset)

        # When the twice-wrapped handler dispatches once.
        result = anyio.run(twice.handler, {"value": "one-call"})

        # Then exactly one handler call and one durable scope row exist.
        assert result == {"ok": {"value": "one-call"}}
        assert calls == [{"value": "one-call"}]
        assert len(_rows(store)) == 1
    finally:
        store.close()


def test_public_gate_captures_active_dataset_at_construction() -> None:
    # Given a gate built while the active dataset lacks its classification.
    calls: list[dict[str, Any]] = []

    async def handler(args: dict[str, Any]) -> dict[str, Any]:
        calls.append(args)
        return {"ok": args}

    registry.set_active(_dataset({}))
    try:
        wrapped = scope.gate(
            _Tool(handler), "scan", "scope-agent", scope.ScopeStore(None, "capture")
        )
        registry.set_active(_dataset({"scan": scope.ExtractorSpec(none=True)}))

        # When the active dataset changes before invocation.
        result = anyio.run(wrapped.handler, {})

        # Then construction-time policy still fails closed and does not dispatch.
        assert result["is_error"] is True
        assert "no scope classification" in result["content"][0]["text"]
        assert calls == []
    finally:
        registry.reset()
