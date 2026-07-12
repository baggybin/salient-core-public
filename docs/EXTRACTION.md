# Extending the Kernel

How a downstream application (the security skin, the tutor showcase, or
your own project) extends `salient-core`.

The kernel plugs into a downstream in two ways: **Protocol contracts** (typed
surfaces you implement) and **runtime registration seams** (`set_*` functions
you call at startup, each with a safe default). This guide covers the load-
bearing Protocols first, then the runtime seams.

## Protocol contracts

### 1. Implement `DaemonServices`

The runner back-injects its owning daemon as `runner._daemon` and uses
it only through the `DaemonServices` Protocol:

```python
from salient_core.protocols import DaemonServices
from salient_core.memory.kg import KnowledgeGraph
from salient_core.coord.questions import QuestionInbox
from salient_core.bus._context_store import ContextStore

class MyDaemon:
    """Implement the five DaemonServices members."""
    profile: dict = {}
    engagement_path: Path | None = None
    context: ContextStore
    kg: KnowledgeGraph
    inbox: QuestionInbox

    def add_question(self, agent: str, question: str, job_id: int | None = None) -> int:
        return self.inbox.add(agent=agent, text=question, job_id=job_id)
```

### 2. Provide a `ToolBuilder`

The kernel's `_runner_factory` needs a callable that builds MCP tool
servers. The kernel ships a stub that raises `NotImplementedError`. A
downstream provides the real implementation:

```python
from salient_core.protocols import ToolBuilder

def my_tool_builder(tool_type: str, config: dict, *, server_name: str | None = None):
    """Build a tool MCP server from a factory type + config."""
    # Return (mcp_server, wire_name, builtin_tool_names)
    ...
```

### 3. Provide an `AliasProtocol` (optional)

If you need custom tool-name mapping between the wire names a model sees and
the kernel's internal names, implement `AliasProtocol` and activate it:

```python
from salient_core import alias

class MyAlias:
    def to_wire(self, name: str) -> str: ...
    def to_real(self, name: str) -> str: ...
    def rewrite_outbound(self, text: str) -> str: ...
    def rewrite_inbound(self, text: str) -> str: ...

alias.set_active(MyAlias())
```

If you don't need aliasing, the kernel default (`IdentityAlias`) passes
everything through unchanged. No action needed.

### 4. Wire the bus

Each agent gets its own bus MCP server:

```python
from salient_core.bus import make_bus

bus_server, server_name, wire_names = make_bus(daemon, agent_name)
```

The bus captures the daemon reference in closures. The ~40 bus tools
(ask_agent, kg_assert, record_review, context_*, etc.) are automatically
wired. To append domain tools, pass `extra_tools=` (a name collision with a
built-in raises rather than silently shadows), or register a wrapping builder
via `set_bus_builder` (below).

## Runtime registration seams

Beyond the Protocols, the kernel exposes a family of `set_*` functions read at
call time (never bound at import). Each has a safe default, so you only call
the ones your skin needs; the kernel runs standalone otherwise.

```python
from salient_core.daemon import _tool_registry, _prompts, _questions
from salient_core.bus import _common, _delegation, _kg, set_bus_builder
from salient_core import alias
from salient_core.policy import registry as policy_registry

# Required to build real tools (default is a fail-loud raising stub):
_tool_registry.set_tool_builder(my_tool_builder)
_tool_registry.set_tool_wire_names({"exec": ["run", "shell"]})   # advertised primary tools
_tool_registry.set_daemon_skin_modules(commands=my_commands_module)

# How daemon.kg is constructed (default builds the local SQLite store; swap in
# e.g. a network client with the same method surface):
_tool_registry.set_kg_builder(lambda db_path: RemoteKnowledgeGraph(url, token))

# Prompt assembly:
_prompts.set_thinking_provider(is_match, resolve)   # model-specific thinking config
_prompts.set_prompts_root("/path/to/prompt/addenda")

# Coordination hooks (all no-op by default):
_delegation.set_delegation_observer(my_observer_factory)
_delegation.set_agent_disabled_checker(lambda daemon, agent: ...)
_kg.set_kg_assert_hook(my_kg_hook)
_common.set_bus_skin_modules(credentials=my_cred_module)
_questions.set_authz_provider(my_authz_config_getter)

# Wrap the bus builder to inject domain tools on every agent's bus:
set_bus_builder(my_bus_builder)

# Data + aliasing:
policy_registry.set_active(my_policy_dataset)   # scope targets, safeguard patterns, structural-transfer tools
alias.set_active(MyAlias())                      # optional, default is IdentityAlias

# SDK capability exposure and policy authorization are separate. `builtin_tools`
# enables SDK capabilities; qualified `tool_targets` entries classify policy
# handling without enabling anything in the SDK:
my_policy_dataset = PolicyDataset(
    tool_targets={
        "builtin.Bash": scope.ExtractorSpec(fields={"command": "raw_argv"}),
        "builtin.Read": scope.ExtractorSpec(local_only=True),
        "builtin.Agent": scope.ExtractorSpec(none=True),
        "bus.context_write": scope.ExtractorSpec(none=True),
    },
    prohibited_patterns=...,
    loud_patterns=...,
    # Deprecated: temporary shadow-only migration input. Remove after every
    # enabled tool has a qualified tool_targets classification.
    trusted_builtins=frozenset({"LegacyKnownTool"}),
)
# TodoWrite, ExitPlanMode, WebSearch, and future SDK names stay absent until their
# schemas and intended policy handling are explicitly known.

# Additive vocabulary seams — each EXTENDS a generic built-in with domain
# specifics (rather than replacing a provider), so the kernel ships a working
# generic default and your skin layers its vocabulary on top:
from salient_core.policy import scope
from salient_core.memory import credentials

scope.register_extractor("my_kind", my_extractor_fn)             # scope target extractor kind
credentials.register_credential_vocab({"ntlm": "has_ntlm_hash"}) # cred kind -> KG predicate
_common.register_secret_fields({"nt_hash", "aes256_key"})        # extra log-redaction field names
_common.register_cred_tool_markers({"secretsdump"})              # tools whose value/hash/token hold secrets
_prompts.register_swarm_bootstrap_addendum("domain swarm guidance …")
```

Migrate one agent at a time:

1. Inventory its actual `builtin_tools` and auto-enabled `Agent`/`Task` tools.
2. Add a qualified `builtin.<name>` classification for every known schema; use
   `none=True` only for a deliberately targetless tool.
3. Run in shadow mode and resolve `builtin_policy_shadow` and
   `legacy_trusted_builtin` records. The legacy field never bypasses safeguards.
4. Remove the tool from `trusted_builtins`, then set
   `enforce_builtin_policy: true`. Enforce mode ignores legacy trust and denies
   any remaining unclassified call before dispatch.

See the seam table in [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for every seam,
its module, and its default.

## Per-agent privilege separation (`_launch_profile`)

To isolate an agent's tool subprocess behind OS-level capability boundaries,
add a `launch:` block to that agent in `agents.yaml`. The daemon passes it
through opaquely as `factory_config["_launch_profile"]`; your tool builder
resolves it to a capability-scoped launcher:

```python
def my_tool_builder(tool_type, config, *, server_name=None):
    launch = config.get("_launch_profile")   # None ⇒ unprivileged default
    if launch:
        # spawn the tool subprocess under the requested capabilities
        ...
```

The kernel never interprets `_launch_profile` — all systemd/capability
mechanism lives skin-side.

## Minimal example

See [`salient-tutor`](https://github.com/baggybin/salient-tutor) for a
complete working example — a teaching agent that composes the kernel's
bus, KG, scheduler, and questions inbox into a Socratic coach.

## Data tables

The kernel ships with empty defaults for scope/safeguard data:

- `ScopeStore(targets={})` — no tool targets
- `SafeguardConfig(patterns={})` — no prohibited patterns

A downstream application populates these with domain-specific data at
startup.
