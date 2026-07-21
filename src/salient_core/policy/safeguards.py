"""Operational safety guards — programmatic blocks that refuse tool
calls matching prohibited-use patterns before they leave the daemon.

This module enforces well-defined operational boundaries. It is NOT a
generic policy engine — scope rules and operator approval serve that
role. All standard dual-use CVP-authorized activity is passed through
without inspection; only explicit boundary violations are refused.

Counter + halt: a runner-level counter increments per match. When it
reaches `halt_threshold` (default 3), the runner halts and the
operator must reset the agent to clear. Lets one false-positive trip
without dooming the engagement.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .registry import PolicyDataset


class OperatorPromptMode(StrEnum):
    LOG = "log"
    SOFT_REFUSE = "soft_refuse"
    HARD_REFUSE = "hard_refuse"


class OperatorPromptModeError(ValueError):
    pass


@dataclass
class SafeguardConfig:
    """Tunables, resolved in priority order:
    agent cfg > engagement profile > defaults."""

    enabled: bool = True
    halt_threshold: int = 3
    operator_prompt_mode: OperatorPromptMode = OperatorPromptMode.LOG
    # Engagement posture — how conservatively the operator paces the run.
    #   "stealth" — least-noise default; high-impact / high-signal
    #               actions are gated at the wire (see check_posture)
    #               until the operator authorizes a louder posture.
    #   "normal"  — today's behavior; nothing extra is gated (default,
    #               so existing engagements are unchanged).
    #   "loud"    — explicitly noisy engagement; posture gating is off.
    # Set under the engagement profile's `safeguards.posture` (or a
    # per-agent `safeguards.posture` override).
    posture: str = "normal"
    # Additional patterns by qualified wire name (e.g. "ssh.ssh_exec"):
    # `list[(label, regex)]`. Use in engagement profiles to add
    # client-specific prohibited patterns (e.g. domain-specific data
    # paths that must never be transferred outside scope).
    extra_patterns: dict[str, list[tuple[str, str]]] = field(default_factory=dict)


# Prohibited-intent markers for natural-language fields (operator prompts,
# inter-agent delegation prompts). The kernel ships an EMPTY default — a
# downstream skin supplies its domain-specific prohibited-intent patterns
# through the PolicyDataset it registers via registry.set_active().
_NATURAL_LANGUAGE_PROHIBITED: list[tuple[str, str]] = []


# Per-qualified-wire-name prohibited patterns (qualified name =
# "<tool_type>.<wire>"). EMPTY by default; the skin supplies its patterns via
# the registered PolicyDataset.


_DEFAULT_PROHIBITED_PATTERNS: dict[str, list[tuple[str, str]]] = {}


# Qualified names that carry inter-agent delegation prose. Operators add
# engagement-specific markers (client codenames, internal project names)
# under the friendly `delegation` key in safeguards.extra_patterns —
# parallel to the `prompt` key for operator prompts — so they don't have
# to know the internal `bus.ask_agent` qualified string. Applied to BOTH
# single (`ask_agent`) and swarm (`ask_agents`) dispatch so a codename
# can't leak through a fan-out the single-target scan would have caught.
_DELEGATION_QUALIFIED: frozenset[str] = frozenset(
    {
        "bus.ask_agent",
        "bus.ask_agents",
    }
)


# Structural checks — beyond regex, some prohibited intents are
# detectable by argument SHAPE (e.g. recursive system-tree copy).
def _structural_block(
    qualified: str,
    tool_input: Mapping[str, Any],
    transfer_tools: frozenset[str],
) -> tuple[str, str] | None:
    """Return (label, reason) if a structural prohibited pattern fires,
    else None. Catches shapes that aren't expressible as regex on
    individual fields. ``transfer_tools`` is the dataset's set of file-transfer
    tool names whose recursive whole-tree transfer is prohibited."""
    if qualified in transfer_tools:
        if tool_input.get("recursive"):
            path = tool_input.get("remote_path") or tool_input.get("local_path") or ""
            if isinstance(path, str):
                p = path.strip().rstrip("/")
                if p in ("", "/", "/home", "/etc", "/var", "/usr", "/root"):
                    return (
                        "unauthorized-mass-system-transfer",
                        f"recursive transfer of {path!r} is a system-wide tree",
                    )
    return None


def _string_haystack(tool_input: Mapping[str, Any]) -> str:
    """Concatenate every string value of a tool input — at ANY nesting
    depth — into one searchable blob, so a regex sweep doesn't care which
    field (or nested options dict) the model put the command/flag in (some
    tools have `command`, others `args`, others `flags`, and some take a
    nested `{"options": {"payload": ...}}`). Walks nested dicts/lists/tuples
    recursively so a prohibited string can't hide one level down."""
    parts: list[str] = []

    def _walk(v: Any) -> None:
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, Mapping):
            for item in v.values():
                _walk(item)
        elif isinstance(v, (list, tuple)):
            for item in v:
                _walk(item)

    _walk(tool_input)
    return " \n".join(parts)


def check_intent(
    qualified: str,
    tool_input: Mapping[str, Any],
    *,
    config: SafeguardConfig | None = None,
    dataset: PolicyDataset | None = None,
) -> tuple[bool, str]:
    """Check a tool call against prohibited use patterns. Returns
    `(allowed, reason)`. `allowed=False` means a safeguard refused;
    `reason` is the matched pattern label, for logging.

    Operator-configured `extra_patterns` are merged on top of the built-in
    set: per-tool patterns under the qualified tool name (e.g.
    `ssh.ssh_exec`), and — for delegation-qualified calls (`ask_agent` /
    `ask_agents`) — engagement-specific delegation-prose patterns under the
    `delegation` key."""
    if config is not None and not config.enabled:
        return True, ""

    haystack = _string_haystack(tool_input)

    from .registry import get_active

    _ds = dataset or get_active()
    prohibited = _ds.prohibited_patterns
    patterns = list(prohibited.get(qualified, []))
    if config is not None:
        patterns.extend(config.extra_patterns.get(qualified, []))
        # Operator-configured delegation-prose patterns ride the friendly
        # `delegation` key (parallel to `prompt`), applied to every
        # delegation-qualified call. Engagement codenames / client markers
        # are scanned here without the operator naming `bus.ask_agent`.
        if qualified in _DELEGATION_QUALIFIED:
            patterns.extend(config.extra_patterns.get("delegation", []))

    for label, pattern in patterns:
        try:
            if re.search(pattern, haystack):
                return False, label
        except re.error:
            # Malformed engagement-supplied regex — skip silently rather
            # than crash the hook. The operator notices via missing
            # blocks on that pattern; the daemon stays up.
            continue

    structural = _structural_block(qualified, tool_input, _ds.structural_transfer_tools)
    if structural is not None:
        return False, structural[0]

    return True, ""


# Valid posture levels, conservative → loud.
_POSTURE_LEVELS: frozenset[str] = frozenset({"stealth", "normal", "loud"})


# High-noise / high-signal techniques, gated ONLY when posture is "stealth".
# Keyed by qualified wire name. These are legitimate, authorized techniques —
# NOT prohibited use — so a posture gate is a soft policy block (no strike
# toward halt), distinct from check_intent. EMPTY by default; the skin supplies
# its posture-gated patterns via the registered PolicyDataset.
_DEFAULT_LOUD_PATTERNS: dict[str, list[tuple[str, str]]] = {}


def check_posture(
    qualified: str,
    tool_input: Mapping[str, Any],
    *,
    posture: str = "normal",
    dataset: PolicyDataset | None = None,
) -> tuple[bool, str]:
    """Gate high-noise techniques by engagement posture. Same return
    shape as `check_intent`: `(allowed, reason)`, where `reason` is the
    matched loud-technique label (for the operator-facing log).

    Only `stealth` gates anything. `normal` (the default) and `loud`
    allow everything, so existing engagements are unchanged. A gated
    call is NOT a prohibited-use strike — the caller should treat it as
    a soft policy block, not increment the safeguard halt counter."""
    if str(posture).strip().lower() != "stealth":
        return True, ""
    from .registry import get_active

    patterns = (dataset or get_active()).loud_patterns.get(qualified)
    if not patterns:
        return True, ""
    haystack = _string_haystack(tool_input)
    for label, pattern in patterns:
        try:
            if re.search(pattern, haystack):
                return False, label
        except re.error:
            continue
    return True, ""


def posture_from_profile(profile: dict[str, Any] | None) -> str:
    """Read the engagement posture from a profile dict's `safeguards`
    block. Returns one of `_POSTURE_LEVELS`, defaulting to "normal"
    (unset / unknown value). Used by the tool-factory layer to pick
    conservative defaults without building a full SafeguardConfig."""
    sg = (profile or {}).get("safeguards") or {}
    p = str(sg.get("posture") or "normal").strip().lower()
    return p if p in _POSTURE_LEVELS else "normal"


# ── Redispatch governor knobs ───────────────────────────────────────────
# Read from the engagement profile's `safeguards.redispatch` block, same
# accessor pattern as `posture_from_profile`. The wire-level
# consecutive-dispatch gate (salient/bus/_delegation.py + the daemon's
# _redispatch_* helpers) reads these.


def redispatch_threshold_from_profile(profile: dict[str, Any] | None) -> int:
    """Consecutive dispatches to a (caller, target) pair before the
    redispatch gate fires. Default 2 (1st free, 2nd+ gated) — matches the
    lead-template 'two consecutive dispatches = stop' ceiling. Floor 2;
    a configured value below 2 is clamped (a threshold of 1 would gate
    even the first dispatch, defeating first-free)."""
    sg = (profile or {}).get("safeguards") or {}
    rd = sg.get("redispatch") or {}
    try:
        n = int(rd.get("threshold", 2))
    except (TypeError, ValueError):
        n = 2
    return max(2, n)


def redispatch_swarm_min_from_profile(profile: dict[str, Any] | None) -> int:
    """Minimum child count at which a bus_trusted ask_agents fan-out is
    batch-gated. Default 2 (all multi-target fan-out is escalation). Floor
    2 (a single-target 'fan-out' isn't a swarm)."""
    sg = (profile or {}).get("safeguards") or {}
    rd = sg.get("redispatch") or {}
    try:
        n = int(rd.get("swarm_min", 2))
    except (TypeError, ValueError):
        n = 2
    return max(2, n)


def redispatch_idle_seconds_from_profile(profile: dict[str, Any] | None) -> float:
    """Idle-TTL forgiveness window: a (caller, target) pair untouched for
    longer than this many seconds is treated as fresh (count 0) on its next
    dispatch. Default 0 == OFF (strict, deterministic — the shipped
    default). Opt in per engagement for long multi-phase work that revisits
    specialists. Note: keyed on wall-clock time, so it's the one piece the
    e2e harness can't drive natively."""
    sg = (profile or {}).get("safeguards") or {}
    rd = sg.get("redispatch") or {}
    try:
        s = float(rd.get("reset_idle_seconds", 0) or 0)
    except (TypeError, ValueError):
        s = 0.0
    return s if s > 0 else 0.0


def consensus_auto_judge_below_from_profile(profile: dict[str, Any] | None) -> float:
    """Agreement-score threshold below which `ask_consensus` (judge="auto")
    invokes the `counsel` LLM judge. Default 0.6. Clamped to [0, 1]; 0 disables
    the auto path (the caller can still force judge="on"). Read from the
    engagement profile's `safeguards.consensus.auto_judge_below`."""
    sg = (profile or {}).get("safeguards") or {}
    cs = sg.get("consensus") or {}
    try:
        v = float(cs.get("auto_judge_below", 0.6))
    except (TypeError, ValueError):
        v = 0.6
    return min(1.0, max(0.0, v))


def consensus_auto_judge_below_semantic_from_profile(profile: dict[str, Any] | None) -> float:
    """Semantic-score threshold below which `ask_consensus` (judge="auto")
    invokes the `counsel` LLM judge. Separate from `auto_judge_below` because
    the two scores live on different scales: embedding cosine between
    topically-related answers runs high (~0.7-0.95 even when they disagree),
    while the sparse atom-overlap score runs low. Default 0.75. Clamped to
    [0, 1]; 0 disables the semantic trigger. Read from the engagement
    profile's `safeguards.consensus.auto_judge_below_semantic`."""
    sg = (profile or {}).get("safeguards") or {}
    cs = sg.get("consensus") or {}
    try:
        v = float(cs.get("auto_judge_below_semantic", 0.75))
    except (TypeError, ValueError):
        v = 0.75
    return min(1.0, max(0.0, v))


def check_prompt_intent(
    prompt: str,
    *,
    config: SafeguardConfig | None = None,
    dataset: PolicyDataset | None = None,
) -> tuple[bool, str]:
    """Scan an operator prompt for natural-language
    operational-boundary markers.

    Same return shape as `check_intent`: `(allowed, reason)`. Callers use this
    for logging, optional hook-specific additional context, or the SDK hook's
    top-level terminal `decision: block`. The daemon job-admission gate remains
    the primary transport-neutral hard-refusal boundary.
    """
    if config is not None and not config.enabled:
        return True, ""
    if not isinstance(prompt, str) or not prompt.strip():
        return True, ""

    from .registry import get_active

    patterns: list[tuple[str, str]] = list((dataset or get_active()).natural_language_prohibited)
    if config is not None:
        # Engagement-supplied extras under the special "prompt" key.
        patterns.extend(config.extra_patterns.get("prompt", []))

    for label, pattern in patterns:
        try:
            if re.search(pattern, prompt, flags=re.IGNORECASE):
                return False, label
        except re.error:
            continue
    return True, ""


def resolve_config(
    agent_cfg: dict[str, Any] | None,
    engagement_profile: dict[str, Any] | None,
) -> SafeguardConfig:
    """Build a SafeguardConfig with precedence:
       agent_cfg.safeguards > engagement_profile.safeguards > defaults.

    `safeguards.posture` (stealth|normal|loud) resolves the same way;
    unknown values fall back to "normal"."""
    cfg = SafeguardConfig()
    profile_block = (engagement_profile or {}).get("safeguards") or {}
    agent_block = (agent_cfg or {}).get("safeguards") or {}

    for source in (profile_block, agent_block):
        if not isinstance(source, dict):
            continue
        if "enabled" in source:
            cfg.enabled = bool(source["enabled"])
        if "halt_threshold" in source:
            try:
                cfg.halt_threshold = max(1, int(source["halt_threshold"]))
            except (TypeError, ValueError):
                pass
        if "posture" in source:
            p = str(source["posture"]).strip().lower()
            if p in _POSTURE_LEVELS:
                cfg.posture = p
        if "operator_prompt_mode" in source:
            try:
                cfg.operator_prompt_mode = OperatorPromptMode(
                    str(source["operator_prompt_mode"]).strip().lower()
                )
            except ValueError as error:
                modes = ", ".join(mode.value for mode in OperatorPromptMode)
                raise OperatorPromptModeError(
                    f"invalid safeguards.operator_prompt_mode "
                    f"{source['operator_prompt_mode']!r}; expected one of: {modes}"
                ) from error
        elif "refuse_operator_prompts" in source:
            warnings.warn(
                "safeguards.refuse_operator_prompts is deprecated; use "
                "operator_prompt_mode: soft_refuse",
                DeprecationWarning,
                stacklevel=2,
            )
            cfg.operator_prompt_mode = (
                OperatorPromptMode.SOFT_REFUSE
                if source["refuse_operator_prompts"] is True
                else OperatorPromptMode.LOG
            )
        extras = source.get("extra_patterns")
        if isinstance(extras, dict):
            for k, v in extras.items():
                if isinstance(v, list):
                    pairs: list[tuple[str, str]] = []
                    for item in v:
                        if isinstance(item, dict) and "label" in item and "pattern" in item:
                            pairs.append((str(item["label"]), str(item["pattern"])))
                        elif isinstance(item, str):
                            pairs.append(("custom", item))
                    if pairs:
                        cfg.extra_patterns.setdefault(str(k), []).extend(pairs)
    return cfg


def __getattr__(name: str) -> Any:
    # Tombstone the relocated public pattern tables: deny/flag patterns are now
    # the injectable ``PolicyDataset.prohibited_patterns`` / ``.loud_patterns``
    # (see policy.registry). A lingering direct import fails loudly rather than
    # silently binding generic patterns into the default-deny safeguards.
    if name in ("PROHIBITED_PATTERNS", "_LOUD_PATTERNS"):
        field = "prohibited_patterns" if name == "PROHIBITED_PATTERNS" else "loud_patterns"
        raise AttributeError(
            f"{name} was replaced by the injectable policy dataset — read "
            f"policy.registry.get_active().{field}, or register your own via "
            f"policy.registry.set_active(PolicyDataset(...)). The kernel default "
            f"lives in policy.defaults.DEFAULT_DATASET."
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
