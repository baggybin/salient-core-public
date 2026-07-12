# salient-core

> A kernel for keeping agents under control: every tool call gated below the
> model, every delegation mediated, every decision on the record.

![salient-core — an agent-control kernel](imgs/social-preview.jpg)

[![CI](https://github.com/baggybin/salient-core/actions/workflows/ci.yml/badge.svg)](https://github.com/baggybin/salient-core/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

`salient-core` is built around a single goal: **give the operator as much
control over agents as possible** — without making the agents useless. Most
agent frameworks optimize for what agents *can* do. This kernel optimizes for
what they *can't* do, and for proving, after the fact, exactly what they did.

Agents run concurrently on your own infrastructure, each scoped to a single
tool surface, coordinated over a typed inter-agent bus — with the operator,
not the model, holding the levers.

## The goal: control

Every capable-agent story ends the same way: the model is smart, the prompt
says "be careful", and nothing *underneath* the model enforces either. The
kernel's answer is to put the control surfaces below the model, where a
confused, manipulated, or simply over-eager agent cannot reason its way past
them:

- **Capability control.** Each agent gets exactly one tool surface, wired at
  startup — not a shared grab-bag. Tool subprocesses are per-agent and can be
  privilege-separated at the OS level via an opaque `_launch_profile` seam, so
  an agent's tools run with only the capabilities that agent was granted.
- **Action control.** Scope and safeguard gates run *below* the model on
  **every** tool invocation and default to **deny**. The authorization
  boundary is transport-neutral: SDK built-in tools, internal bus tools,
  external MCP servers, and even model-emitted text commands are all
  classified against the same policy before anything executes. Capability
  exposure and authorization are deliberately separate — enabling a tool never
  implicitly authorizes it, and an unclassified tool fails closed. A denied
  call never runs.
- **Delegation control.** Agents don't spawn agents at will. Delegation flows
  over the typed bus, is observable, and is **operator-mediated**: anything
  that needs a human lands in a typed question inbox and waits. Cycle
  detection, loop cooldowns, and operator kill-switches (disable an agent and
  routing skips it) keep a runaway swarm from spinning.
- **Accountability.** Every scope decision, tool call, and operator answer is
  persisted — with secrets redacted, and with both raw and redacted snapshots
  audited — so you can reconstruct exactly what each agent did, what was
  allowed or denied, and why. If an audit record can't be written, the store
  flags itself degraded rather than staying silent. Built for work you must be
  able to *prove*, not merely trust.
- **Staged trust.** New policy never has to be a leap: the authorization
  boundary ships with a **shadow mode** that records what *would* be denied
  while still permitting dispatch, so you can mine real traffic, classify
  every tool, and only then flip `enforce_builtin_policy: true`.

The kernel was extracted from Salient, a private multi-agent system operating
in a domain where the cost of a wrong action is high. The domain-specific code
stayed behind; what's here is the control and coordination layer, which
generalizes to any setting where agents must be constrained.

**Showcase application:** [salient-tutor](https://github.com/baggybin/salient-tutor) —
a Socratic teaching agent built on this kernel.

## How it works

Every agent runs its own provider loop — the Claude Agent SDK by default, or
OpenAI Codex via the optional `codex` extra — with a single **bus MCP server**
attached. When an agent calls a tool, the call passes through the **scope +
safeguard gates** *before* it executes; anything that needs a human is routed
to the **operator inbox**; what agents learn is corroborated into a shared
**knowledge graph**. The kernel's value is this topology, not any one box.

A denied call never runs. A delegation to another agent, or a decision the
model isn't allowed to make alone, lands in the operator inbox as a typed
question and waits for an answer. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full data-flow and
persistence model, and
[`docs/KERNEL-HARDENING-v0.6.0.md`](docs/KERNEL-HARDENING-v0.6.0.md) for the
engineering log of the review that hardened the authorization boundary.

<p align="center">
  <img src="imgs/without-kernel-comparison.png" alt="Without the kernel: chaotic cycles, stalls, leaked intent. With salient-core: a typed bus, cycle detection, and operator gates." width="900">
</p>

## Where it sits

salient-core is **not competing with orchestration frameworks** on workflow
expressiveness — LangGraph will always have more graph shapes, CrewAI more
role templates. It occupies a different axis: how much enforced control the
operator keeps while agents run. If your problem is "compose LLM calls into a
pipeline", use an orchestrator. If your problem is "let agents act, but never
outside the box I drew, and show me the receipts", that is what this kernel
is for.

| | salient-core | LangGraph | CrewAI / AutoGen |
|---|---|---|---|
| **Optimizes for** | operator control over agents | workflow expressiveness | role-based collaboration |
| **Coordination primitive** | typed **MCP bus** per agent | in-process state graph | in-process agent/role objects |
| **Policy / gating** | **default-deny gate below the model**, per tool call, transport-neutral | prompt- / code-level, in-graph | prompt-level convention |
| **Human-in-the-loop** | first-class **operator inbox** (typed Q/A) | interrupts / checkpoints | optional human proxy |
| **Auditability** | **redacted, replayable trail** of every gate decision + tool call | app-level logging | app-level logging |
| **Cross-session memory** | **noisy-OR knowledge graph** w/ corroboration + embeddings | checkpointer state | external memory add-ons |
| **Isolation** | per-agent tool subprocess, optional privilege separation | shared process | shared process |
| **Backends** | Claude SDK + OpenAI Codex (provider seam for more) | many LLMs | many LLMs |

The trade is deliberate: salient-core is narrower (a library kernel, not a
hosted runtime) in exchange for **enforced** scoping and **mediated**
delegation — built for settings where agents must be *constrained*, not merely
orchestrated.

**When *not* to use it:** single-agent workflows (the control plane is
overhead you don't need), model providers beyond Claude and OpenAI Codex today
(others plug in behind the provider seam but none ship yet), or if you want a
no-code / hosted orchestration runtime — this is a library kernel you wire
into your own daemon.

## What's in the kernel

| Component | What it does |
|---|---|
| **Policy gates** | Scope + safeguards enforced *below* the model — default-deny on every tool invocation, across every transport (SDK built-ins, bus tools, external MCP, model-emitted text), with a shadow→enforce rollout path |
| **Audit trail** | Scope decisions, tool I/O, and operator answers persisted with secret redaction — a replayable record of what ran and what was denied, plus a sticky degraded-health flag when a record can't be written |
| **Operator inbox** | Typed question/answer pattern for anything that needs a human decision |
| **Bus-as-MCP** | ~40 typed inter-agent tools (delegation, context, KG, discovery, audit) exposed as a single MCP server per agent, with an `extra_tools` slot for domain add-ons |
| **Noisy-OR KG** | Cross-session knowledge graph with corroboration, embeddings, subject-namespace scoping, provenance, and archive-first compaction |
| **SM-2 scheduler** | Spaced-repetition gradebook for durable recall tracking |
| **[`ask_fable`](src/salient_core/ask_fable/README.md)** | Gated MCP sidecar: any agent can request narrow code/architecture reasoning from Fable (`claude-fable-5`), behind the same denylist guard + a hashed, owner-only audit log — concrete proof the policy gates are real, not aspirational (optional `[ask-fable]` extra) |
| **Runner** | Provider-neutral: the **Claude Agent SDK** is the primary backend, and an **OpenAI Codex** provider ships behind the optional `[codex]` extra (thread runtime + an MCP gateway so Codex agents use the same bus and pass the same gates). Further providers register via the `salient.agent_providers` entry point behind the `AgentBackend` seam. Per-agent tool subprocesses can be privilege-separated via an opaque `_launch_profile` seam |

## Requirements

- **Python ≥ 3.11, < 3.14**
- **[`claude-agent-sdk`](https://pypi.org/project/claude-agent-sdk/) `>=0.2.110,<0.3`** —
  pulled in automatically. The runner drives Claude agents through it, so you
  need Claude access: either an `ANTHROPIC_API_KEY`, or (for the `ask_fable`
  sidecar) an existing Claude Code OAuth session.
- Optional extra: `pip install 'salient-core[ask-fable]'` adds the `mcp`
  transport for the [`ask_fable`](src/salient_core/ask_fable/README.md) reasoning
  server.
- Optional extra: `pip install 'salient-core[codex]'` adds the **OpenAI Codex
  provider**, so agents can run on Codex instead of the Claude SDK (bus access
  via an MCP gateway; requires your own Codex/OpenAI auth).

> **Default-deny, out of the box.** The kernel ships with an *empty* scope and
> safeguard dataset, and the scope gate defaults to **deny** — an engagement
> with no scope set refuses **every** tool call. Populate `ScopeStore` /
> `SafeguardConfig` at startup (see [`docs/EXTRACTION.md`](docs/EXTRACTION.md#data-tables))
> before agents can do anything. This is intentional: policy is opt-in-safe.

## Quick start

```bash
pip install salient-core
```

### Run the multi-agent showcase

The kernel's actual job — fanning one prompt across a panel of agents over the
bus, capturing each leg's reasoning, and scoring **semantic convergence** —
runs offline with no API key:

```bash
pip install salient-core starlette uvicorn
cd examples/consensus_panel
uvicorn server:app --reload      # → http://127.0.0.1:8055
```

This exercises the real `ask_consensus` machinery
(`salient_core.bus._consensus`): same-prompt fan-out, per-leg trace capture,
embedding-based agreement scoring, and the parameterizable judge. See
[`examples/consensus_panel/`](examples/consensus_panel/README.md) for how to
swap the mock runner for live models. For a full application built on the
kernel, see [`salient-tutor`](https://github.com/baggybin/salient-tutor).

### Standalone modules

Several pieces work without wiring up the full daemon — e.g. the SM-2
scheduler and the knowledge graph:

```python
from salient_core.tutor.schedule import next_interval_days, next_mastery

interval = next_interval_days(prev_days=7.0, grade="good")  # → ~16.1
mastery = next_mastery(prev_mastery=0.5, grade="easy")      # → ~0.75
```

## Seams

The kernel ships no app-specific ("skin") code. Instead it exposes two kinds of
plug-in points, and a downstream application (a domain skin, the tutor
showcase, or your own project) fills them in at startup:

- **Protocol contracts** — the typed surfaces a downstream implements
  (`DaemonServices`, `ToolBuilder`, `AliasProtocol`, `AgentBackend` in
  `salient_core.protocols`).
- **Runtime registration seams** — a family of `set_*` functions read at *call
  time* (never import time), each with a safe default so the kernel stays
  runnable standalone (e.g. `set_bus_builder`, `set_tool_builder`,
  `set_thinking_provider`, `set_kg_assert_hook`, `alias.set_active`).

```python
from salient_core.protocols import DaemonServices, ToolBuilder, AliasProtocol

class MyDaemon:
    """A downstream daemon implements DaemonServices."""
    profile: dict
    engagement_path: Path | None
    context: ContextStore
    kg: KnowledgeGraph
    inbox: QuestionInbox

    def add_question(self, agent: str, question: str, job_id: int | None = None) -> int: ...
```

See [`docs/EXTRACTION.md`](docs/EXTRACTION.md) for the full guide and the
complete seam catalogue in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module map,
data flow, and Protocol seams.

## Status

Pre-alpha. APIs are evolving. See [`CHANGELOG.md`](CHANGELOG.md) for release
history.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
