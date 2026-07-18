from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from .decision import FrozenInput, FrozenValue, InputValue, ToolInvocation
from .scope_audit import ScopeAudit, scope_audit

if TYPE_CHECKING:
    from .registry import PolicyDataset
    from .scope import ExtractorSpec, ScopeStore, Target


class ScopeEvaluationKind(StrEnum):
    """Exhaustive scope branches independent of a transport response type."""

    UNCLASSIFIED = "unclassified"
    TARGETLESS = "targetless"
    SESSION_BYPASS = "session_bypass"
    LOCAL_ONLY = "local_only"
    EXTRACTION_DENIED = "extraction_denied"
    EMPTY_TARGETS = "empty_targets"
    STRICT = "strict"
    RESEARCH = "research"


@dataclass(frozen=True, slots=True)
class ScopeEvaluation:
    """A scope verdict that adapters can render without importing SDK types."""

    allowed: bool
    kind: ScopeEvaluationKind
    reason: str
    targets: tuple[Target, ...]
    classification_key: str | None


@dataclass(frozen=True, slots=True)
class ScopeEvaluationRequest:
    """Adapter-selected dataset and permission to use the research lane."""

    dataset: PolicyDataset | None = None
    allow_research: bool = True


def _thaw(value: FrozenValue) -> InputValue:
    match value:
        case Mapping():
            return {str(key): _thaw(nested) for key, nested in value.items()}
        case tuple():
            return [_thaw(item) for item in value]
        case str() | int() | float() | bool() | None:
            return value


def _thaw_input(value: FrozenInput) -> dict[str, InputValue]:
    return {key: _thaw(nested) for key, nested in value.items()}


def _resolved_spec(
    invocation: ToolInvocation,
    dataset: PolicyDataset,
) -> tuple[str | None, ExtractorSpec | None]:
    qualified = invocation.qualified_name
    spec = dataset.tool_targets.get(qualified)
    if spec is not None:
        return qualified, spec
    bare = qualified.rpartition(".")[2]
    return (bare, dataset.tool_targets[bare]) if bare in dataset.tool_targets else (None, None)


def _record(
    invocation: ToolInvocation,
    store: ScopeStore,
    audit: ScopeAudit,
) -> None:
    store.log_decision(
        agent=invocation.agent_id,
        tool=invocation.wire_name,
        args=_thaw_input(invocation.audit_input),
        targets=list(audit.targets),
        result=audit.result,
    )


async def evaluate_scope(
    invocation: ToolInvocation,
    store: ScopeStore,
    dataset: PolicyDataset | ScopeEvaluationRequest | None = None,
    *,
    mode: Literal["enforce", "probe"] = "enforce",
) -> ScopeEvaluation:
    """Classify, evaluate, and durably record at most one scope decision.

    ``mode="probe"`` computes the IDENTICAL verdict but READ-ONLY: it writes no
    audit row and consumes no one-shot rule (routes the strict lane through
    ``store.dry_check`` — the read-only twin of ``store.check``). The enforce
    path is byte-for-byte unchanged. A caller previewing what the gate WOULD
    decide (the ``scope gate-probe`` RPC) passes ``mode="probe"``; the gate
    dispatch never does. Verdict parity is pinned by the enforce==probe matrix
    test in tests/ — the anti-drift guarantee that the probe cannot lie.
    """
    from . import scope
    from .registry import PolicyDataset, get_active

    def _emit(audit: ScopeAudit) -> None:
        # Single choke point for the durable audit write: it happens ONLY when
        # enforcing. A new evaluate_scope branch that calls _emit cannot leak an
        # audit row into probe mode, because it never touches `mode` itself.
        if mode == "enforce":
            _record(invocation, store, audit)

    match dataset:
        case ScopeEvaluationRequest(dataset=request_dataset, allow_research=allow_research):
            active_dataset = request_dataset or get_active()
        case PolicyDataset():
            active_dataset = dataset
            allow_research = True
        case None:
            active_dataset = get_active()
            allow_research = True
    classification_key, spec = _resolved_spec(invocation, active_dataset)
    if spec is None:
        check = scope.CheckResult(
            allowed=False,
            decisions=[],
            summary=f"tool {invocation.wire_name!r} has no scope classification",
        )
        _emit(scope_audit(invocation, (), check))
        return ScopeEvaluation(
            allowed=False,
            kind=ScopeEvaluationKind.UNCLASSIFIED,
            reason=(
                f"tool {invocation.wire_name!r} has no scope classification — "
                "refusing fail-closed. Add an entry to the active "
                "PolicyDataset.tool_targets (policy.registry.set_active)."
            ),
            targets=(),
            classification_key=None,
        )
    if spec.none:
        return ScopeEvaluation(
            allowed=True,
            kind=ScopeEvaluationKind.TARGETLESS,
            reason="targetless tool — scope check skipped",
            targets=(),
            classification_key=classification_key,
        )
    if spec.session_scoped and not store.session_strict():
        return ScopeEvaluation(
            allowed=True,
            kind=ScopeEvaluationKind.SESSION_BYPASS,
            reason="session-scoped tool — strict session checking disabled",
            targets=(),
            classification_key=classification_key,
        )
    if spec.local_only:
        check = scope.CheckResult(
            allowed=True,
            decisions=[],
            summary="local-only tool — scope check skipped",
        )
        _emit(scope_audit(invocation, (), check))
        return ScopeEvaluation(
            allowed=True,
            kind=ScopeEvaluationKind.LOCAL_ONLY,
            reason=check.summary,
            targets=(),
            classification_key=classification_key,
        )

    try:
        extracted = tuple(scope.extract_targets(spec, _thaw_input(invocation.evaluation_input)))
    except scope.ExtractorError as error:
        check = scope.CheckResult(
            allowed=False,
            decisions=[],
            summary=f"extractor: {error}",
        )
        _emit(scope_audit(invocation, (), check))
        return ScopeEvaluation(
            allowed=False,
            kind=ScopeEvaluationKind.EXTRACTION_DENIED,
            reason=f"extractor refused: {error}",
            targets=(),
            classification_key=classification_key,
        )
    if not extracted:
        check = scope.CheckResult(
            allowed=True,
            decisions=[],
            summary="extraction returned no targets — call allowed",
        )
        _emit(scope_audit(invocation, (), check))
        return ScopeEvaluation(
            allowed=True,
            kind=ScopeEvaluationKind.EMPTY_TARGETS,
            reason=check.summary,
            targets=(),
            classification_key=classification_key,
        )

    use_research = allow_research and spec.research and store.research_active()
    if use_research:
        loop = asyncio.get_running_loop()
        check = await loop.run_in_executor(
            scope._RESEARCH_EXECUTOR,
            store.check_research,
            list(extracted),
            spec.research_active,
        )
        kind = ScopeEvaluationKind.RESEARCH
    else:
        # Probe mode uses dry_check — identical verdict, never consumes a
        # one-shot rule. (The research lane's check_research is already
        # store-read-only, so it needs no probe variant.)
        run_check = store.check if mode == "enforce" else store.dry_check
        check = run_check(list(extracted))
        kind = ScopeEvaluationKind.STRICT
    _emit(scope_audit(invocation, extracted, check))
    if check.allowed:
        return ScopeEvaluation(
            allowed=True,
            kind=kind,
            reason=check.summary,
            targets=extracted,
            classification_key=classification_key,
        )

    example = extracted[0].value
    if use_research:
        reason = (
            f"research target refused — {check.summary}\n\n"
            "The research lane reaches any PUBLIC host but denies "
            "internal/private infrastructure and `out_targets`. To "
            "reach an internal target, add it to engagement scope: "
            f"`salientctl scope add {example} --reason '…'`."
        )
    else:
        reason = (
            f"out of scope — {check.summary}\n\n"
            "To allow: `salientctl scope add <pattern> --reason '…'` "
            "(or `--once` for single-use). "
            f"To inspect: `salientctl scope test {example}` "
            "or `salientctl scope deny-log --since 5m`."
        )
    return ScopeEvaluation(
        allowed=False,
        kind=kind,
        reason=reason,
        targets=extracted,
        classification_key=classification_key,
    )


__all__ = [
    "ScopeEvaluation",
    "ScopeEvaluationKind",
    "ScopeEvaluationRequest",
    "evaluate_scope",
]
