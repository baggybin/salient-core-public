# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.6] - 2026-07-12

Second public snapshot, consolidating the `0.7.x` line (`0.7.0`–`0.7.6`).

### Added
- **Codex runtime provider**: a provider-neutral runner seam (`providers.py`,
  `runtime.py`) so agents can run on OpenAI Codex as well as the Claude SDK —
  `codex.py` (thread runtime, reasoning-effort wiring, persona via
  `baseInstructions`) and `codex_mcp.py` (MCP gateway so codex agents can use
  the bus). Install with the optional `codex` extra.
- Codex MCP tool calls are surfaced as tool-call / tool-result events, and
  streamed text is coalesced to one event/message.

### Changed
- Bus substitute routing skips operator-disabled candidates.
- `ask_agents` "any" mode cancels sibling legs like "race".
- README repositioned around the project's actual goal — maximum operator
  control over agents — rather than orchestration-framework comparison; Codex
  provider and the `codex` extra documented.
- Package metadata and in-repo links point at the canonical repository names
  (`baggybin/salient-core`, `baggybin/salient-tutor`).

### Fixed
- Runner no longer re-prompts a delegated agent that replied in text
  (silent-completion detection).
- Read/poll tools (e.g. `context_read`) are exempt from loop detection, and
  loop questions get a cooldown so operators aren't re-asked in a tight loop.
- Codex provider errors surface the real cause instead of a bare
  "Codex provider error"; long-running `ask_*` gateway calls get an adequate
  blocking timeout.

## [0.6.0] - 2026-07-10

Kernel-hardening release: a transport-neutral tool-authorization boundary plus
a 7-finding invariant review, all closed with regression tests. See
[`docs/KERNEL-HARDENING-v0.6.0.md`](docs/KERNEL-HARDENING-v0.6.0.md) for the
engineering log. (Consolidates the untagged `0.5.0` KG work.)

### Added
- **Transport-neutral tool-authorization boundary**: every tool invocation —
  SDK built-ins, internal MCP, external MCP, and model-emitted text — is
  classified and gated below the model via qualified
  `PolicyDataset.tool_targets` entries (`policy/decision.py`,
  `daemon/_policy_hook_adapter.py`, `daemon/_text_policy.py`). Capability
  exposure and policy authorization are separate; unknown tools fail closed.
  Staged rollout: shadow mode records denials, `enforce_builtin_policy: true`
  makes them effective. Raw-vs-redacted dual audit snapshots
  (`policy/redaction.py`, `policy/scope_audit.py`).
- **KG transactional writes + snapshot readers**: one-writer /
  snapshot-isolated-readers connection discipline; a mutating method that
  raises mid-transaction rolls back cleanly. `set_kg_builder` seam for
  substituting a network-backed KnowledgeGraph. `Fact.source_ref` provenance.
- **Subject-prefix scoping on `KnowledgeGraph.query` / `neighbors` /
  `embedding_counts`**: optional `subject_prefix` keyword restricts reads to
  a subject namespace, matched in SQL via the `kg_subject` index (LIKE,
  escaped). For `neighbors`, the BFS only follows in-prefix edges, so the walk
  stays bounded by the namespace size rather than a foreign hub's degree.
  Backward-compatible: `None`/`""` is the unrestricted behavior.

### Fixed
- `ContextStore` commit failures roll back the transaction (no dirty
  transaction flushed by a later commit); the connection is invalidated if
  rollback itself fails.
- Compaction deletes exactly the archived id set with a delete-time expiry
  re-check — a fact revived between archive and delete is no longer lost.
- `ExtractorSpec.fields` is frozen after registration
  (`MappingProxyType`), so active policy can't be mutated.
- `ask_agent`'s non-detached child-stop is awaited (bounded, shielded) and
  joined at teardown via `track_background` / `join_background_tasks`.
- `ContextStore.health()` attributes every degraded sink with per-sink counts.
- Startup SQLite `_peek_*` readers no longer leak connection handles.
- `runner.submit()` contract violations raise an actionable `TypeError`
  instead of an opaque `NoneType.id` crash.

## [0.4.0] - 2026-07-07

First public snapshot. Consolidates the pre-public `0.3.x`–`0.4.0` kernel work
and prepares the repository for open-source release.

### Added
- Runnable in-repo showcase: `examples/consensus_panel/` — an offline bus demo
  of the `ask_consensus` fan-out with semantic-convergence scoring.

### Changed
- README rebuilt as an adopter on-ramp: "Why / when-not-to-use" motivation,
  a "How it works" flow diagram, a positioning table vs. LangGraph/CrewAI/
  AutoGen, a Requirements section, a default-deny callout, and the `ask_fable`
  sidecar surfaced in the feature table.
- Package metadata and in-repo links point at the public repository
  (`baggybin/salient-core-public`); `__version__` synced to the packaged
  version (`0.4.0`).

### Added
- **Per-agent privilege separation seam**: the daemon injects an agent's
  `launch:` block from `agents.yaml` into `factory_config` under the opaque
  `_launch_profile` key (`daemon/_runner_factory.py`). The kernel never
  interprets it — a downstream tool builder resolves it to a capability-scoped
  subprocess launcher. Absent `launch:` ⇒ key not injected ⇒ unprivileged
  default. Mirrors the existing `_posture` / `_scope_networks` /
  `_authed_sessions` injection convention.

## [0.1.0] - 2026-07-06

Kernel convergence complete — mechanism + seams, single source of truth.
`salient-core` is now independently importable and testable, carrying only
generic coordination mechanism plus registration seams (zero references to
app-specific "skin" modules).

### Added
- **Runtime seam model** — call-time registration points (not import-time
  binds), each with a safe default, so a downstream skin plugs in at startup
  while the kernel stays runnable standalone: `set_bus_builder`
  (`bus/__init__.py`), `set_bus_skin_modules` (`bus/_common.py`),
  `set_kg_assert_hook` (`bus/_kg.py`), `set_delegation_observer` /
  `set_agent_disabled_checker` (`bus/_delegation.py`), `set_tool_builder` /
  `set_tool_wire_names` / `set_daemon_skin_modules` (`daemon/_tool_registry.py`),
  `set_thinking_provider` / `set_prompts_root` (`daemon/_prompts.py`),
  `set_authz_provider` (`daemon/_questions.py`), plus `alias.set_active` and
  `policy.registry.set_active`.
- **`@bus_tool` migration** — every bus tool family (`_context`, `_kg`,
  `_discovery`, `_credentials`, `_delegation`, `_lifecycle`, `_audit`, skills,
  lessons) now derives its wire schema from a Pydantic model and validates
  model args before the handler runs (`bus/_common.py`), with typed `BusFlags`
  (`bus/_flags.py`) carrying routing/write-back on the `.trusted` channel.
  Golden-master wire-schema snapshots (`tests/golden/bus_schemas/`) pin each
  schema byte-for-byte. Rubric documented in `docs/BUS_TOOL_FIELDS.md`.
- **Bus extensibility** — `make_bus` accepts an `extra_tools` slot so a skin can
  append domain tools; a name collision with a built-in raises rather than
  silently shadows.
- Kernel extraction from the upstream `salient` orchestrator: `bus/` (typed
  inter-agent tools incl. `ask_consensus` with semantic scoring, judge, and
  per-leg traces), `memory/` (noisy-OR knowledge graph, embeddings,
  `semantic_recall`), `coord/` (question inbox, delegation graph), `daemon/`
  (Claude-SDK agent runner behind the `DaemonServices` Protocol seam),
  `policy/` (scope + safeguards gates), `tutor/` (SM-2 scheduler +
  learner-gradebook bucketing), `protocols.py` seams, `alias.py` passthrough.
- Sealed public API: curated lazy exports at the top level (`__all__`,
  PEP 562), `py.typed` (PEP 561), `semantic_recall` / `bucketed_profile`
  convenience helpers.
- `examples/consensus_panel/` — split-pane consensus showcase (Starlette SSE
  server + offline mock runner scored by the kernel's real
  `semantic_agreement`).
- Public-release docs: `README.md`, `docs/ARCHITECTURE.md`,
  `docs/EXTRACTION.md`.
- Repository bootstrap: `pyproject.toml` (src layout, Apache 2.0, Python ≥3.11),
  `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.gitignore`,
  `.pre-commit-config.yaml`, CI workflow (ruff + mypy + pytest --cov).
- `PLAN.md` — comprehensive extraction + showcase plan (Path A).

### Fixed
- Public-surface contract fixes: `semantic_recall` never raises;
  `alias.__all__` matches the documented API; consensus judge honors
  `prefer_primary` and reports accurate skip reasons; per-leg consensus
  traces isolated by child job id; zero-norm vectors excluded from
  `semantic_agreement`.
- Prompt addenda moved into the package (`salient_core/prompts/`) so the
  runner factory finds them from a checkout and an installed wheel alike.

## [0.0.1] - 2026-06-30

### Added
- Empty package skeleton. No kernel modules yet — see `PLAN.md` for the
  extraction roadmap.
