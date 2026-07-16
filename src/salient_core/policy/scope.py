"""Deterministic scope enforcement for tool invocations.

Every tool call is checked against an engagement allowlist (loaded from
`engagement.yaml`) plus operator-added adhoc rules, in pure Python,
BEFORE the tool subprocess is spawned. The LLM cannot bypass this — the
check happens inside the MCP handler wrapper, between the SDK routing
a ToolUseBlock and the tool's original body running.

Default is DENY. An engagement with no scope set refuses every
target-bearing tool call until the operator runs `prefs set scope.in_targets …`
or `salientctl scope add …`.

See docs/SCOPE.md for the full design — invariant, threat model, the
two scope sources, the four extractor kinds, the deny UX, and the
audit-log format.

Public surface (everything else is internal):

    Target, ScopeRule, Decision, CheckResult — data classes
    ExtractorError — raised by extractors when args can't be parsed
    ScopeStore — the one stateful object; owned by Daemon
    gate(sdk_tool, wire_name, agent_name, store) → SdkMcpTool
    TOOL_TARGETS — central extractor-spec table, classified per wire name
    parse_rule(pattern) → (kind, normalized_pattern)
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import re
import socket
import sqlite3
import subprocess
import time
import unicodedata
import urllib.parse
from collections.abc import Awaitable, Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, get_args

from .decision import InvocationIdentity, InvocationTransport, ToolInvocation
from .scope_evaluation import evaluate_scope

if TYPE_CHECKING:
    from .registry import PolicyDataset

# ─── data model ─────────────────────────────────────────────────────────────

TargetKind = Literal["ip", "network", "host", "url", "wifi_bssid", "wifi_ssid"]
RuleKind = Literal["network", "host_glob", "host_exact", "wifi_bssid", "wifi_ssid"]
Direction = Literal["in", "out"]
Origin = Literal["engagement", "adhoc"]
Verdict = Literal["allow", "deny"]


@dataclass(frozen=True)
class Target:
    """One thing a tool wants to talk to.

    `value` is canonical: IPs/networks are `str(ipaddress.ip_*)`,
    hosts are lowercased + IDNA-normalized, URLs are reduced to host.
    """

    kind: TargetKind
    value: str
    source_field: str  # which arg field this came from, for error messages


@dataclass(frozen=True)
class ScopeRule:
    pattern: str
    kind: RuleKind
    direction: Direction
    origin: Origin
    added_by: str
    added_at: float
    expires_at: float | None = None
    one_shot: bool = False
    consumed_at: float | None = None
    reason: str = ""

    def is_active(self, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        if self.expires_at is not None and now >= self.expires_at:
            return False
        if self.one_shot and self.consumed_at is not None:
            return False
        return True


@dataclass(frozen=True)
class Decision:
    target: Target
    verdict: Verdict
    matched_rule: ScopeRule | None
    reason: str


@dataclass(frozen=True)
class CheckResult:
    allowed: bool
    decisions: list[Decision]
    summary: str


class ExtractorError(ValueError):
    """An extractor refused the args (unparseable, obfuscated, required field
    missing). The gate denies with `str(exc)` as the reason."""


# ─── pattern parsing ───────────────────────────────────────────────────────


def parse_rule(
    pattern: str,
    *,
    force_kind: str | None = None,
) -> tuple[RuleKind, str]:
    """Classify and canonicalize a rule pattern.

    Raises ValueError if the pattern is not a recognized shape.

    Returns (kind, normalized_pattern):
        "10.0.0.0/24"      → ("network",   "10.0.0.0/24")
        "10.0.0.5"         → ("network",   "10.0.0.5/32")    # single IP → /32 network
        "2001:db8::/64"    → ("network",   "2001:db8::/64")
        "*.example.internal" → ("host_glob", "*.example.internal")
        "example.internal"   → ("host_exact","example.internal")

    `force_kind="wifi"` switches to wifi parsing:
        "70:a7:41:e1:05:96" → ("wifi_bssid", "70:A7:41:E1:05:96")
        "70-a7-41-e1-05-96" → ("wifi_bssid", "70:A7:41:E1:05:96")
        "MyHomeWiFi"        → ("wifi_ssid",  "MyHomeWiFi")     # case preserved
    """
    if force_kind == "wifi":
        return _parse_wifi_rule(pattern)
    if force_kind not in (None, "wifi"):
        raise ValueError(f"unsupported force_kind {force_kind!r}")
    s = (pattern or "").strip().lower().rstrip(".")
    if not s:
        raise ValueError("empty pattern")

    # Network / IP
    if _looks_ip_or_network(s):
        try:
            if "/" in s:
                net = ipaddress.ip_network(s, strict=False)
            else:
                addr = ipaddress.ip_address(s)
                # Single IP → /32 or /128 network for uniform membership check.
                net = ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
            return "network", str(net)
        except ValueError as e:
            raise ValueError(f"bad network pattern {pattern!r}: {e}") from e

    # Host glob (must contain *)
    if "*" in s:
        # Require the wildcard to be a leading "*." and the rest be a valid
        # hostname suffix. We don't accept arbitrary fnmatch patterns —
        # that produces too much surface area for ambiguous globs.
        if not s.startswith("*."):
            raise ValueError(f"only leading '*.suffix' wildcards are supported, got {pattern!r}")
        suffix = s[2:]
        if not suffix or not _looks_hostname(suffix):
            raise ValueError(f"bad host-glob pattern {pattern!r}")
        return "host_glob", s

    # Bare hostname
    if _looks_hostname(s):
        return "host_exact", s

    raise ValueError(
        f"unrecognized scope pattern {pattern!r} — expected IP, CIDR, hostname, or '*.suffix' glob"
    )


# ─── wifi (BSSID / SSID) parsing ───────────────────────────────────────────
#
# 802.11 BSSID is a MAC address; canonical form is six uppercase hex pairs
# joined by ':' (IEEE 802 std). Operators paste in colon-, dash-, or dot-
# separated forms — we normalize to the canonical form for storage.
#
# SSIDs are 0-32 byte strings, case-sensitive per 802.11. We require 1-32
# chars and preserve case exactly.

_RX_BSSID = re.compile(r"^[0-9a-f]{2}([:\-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}$", re.IGNORECASE)


def _normalize_bssid(s: str) -> str:
    """Canonicalize a BSSID/MAC to 'XX:XX:XX:XX:XX:XX' (uppercase, colons).
    Raises ValueError on bad shape."""
    s = (s or "").strip()
    if not _RX_BSSID.match(s):
        raise ValueError(f"bad BSSID {s!r} — expected 6 hex pairs separated by ':' or '-'")
    return s.upper().replace("-", ":")


def _looks_bssid(s: str) -> bool:
    return bool(_RX_BSSID.match((s or "").strip()))


def _parse_wifi_rule(pattern: str) -> tuple[RuleKind, str]:
    """Parse a `--wifi` scope pattern.

    BSSID shape (`XX:XX:XX:XX:XX:XX` or dashes) → wifi_bssid (canon uppercase
    colons). Anything else → wifi_ssid (1-32 chars, case preserved).
    """
    s = (pattern or "").strip()
    if not s:
        raise ValueError("empty pattern")
    if _looks_bssid(s):
        return "wifi_bssid", _normalize_bssid(s)
    if len(s.encode("utf-8")) > 32:
        raise ValueError(f"SSID {s!r} exceeds 32 bytes — 802.11 SSIDs are 0-32 bytes")
    return "wifi_ssid", s


_RX_IPV4_SHAPE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_RX_IPV6_SHAPE = re.compile(r"^[0-9a-f:]+(?:/\d{1,3})?$", re.IGNORECASE)
_RX_HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

# Common file-extension TLDs that pattern-match the hostname regex but are
# obviously local filenames (pcap captures, hash dumps, config files,
# binaries, scripts, etc.). When a binary_argv / raw_argv token has one of
# these as its final label, classify it as "not a host" so the scope gate
# doesn't refuse on what's actually a file path. New extensions: lowercase,
# no dot, append below.
_FILE_EXT_TLDS = frozenset(
    {
        # Packet captures
        "pcap",
        "pcapng",
        "cap",
        # Generic data formats
        "txt",
        "log",
        "json",
        "csv",
        "tsv",
        "xml",
        "yaml",
        "yml",
        "toml",
        "ini",
        "md",
        "rst",
        "html",
        "htm",
        "pdf",
        # Binaries / objects
        "bin",
        "exe",
        "dll",
        "so",
        "elf",
        "obj",
        "o",
        "a",
        "lib",
        "ko",
        # Scripts / source
        "py",
        "sh",
        "rb",
        "pl",
        "ps1",
        "bat",
        "cmd",
        "js",
        "ts",
        "go",
        "rs",
        "c",
        "h",
        "cpp",
        "cc",
        "java",
        "class",
        "jar",
        "wasm",
        # Archives
        "zip",
        "tar",
        "gz",
        "bz2",
        "xz",
        "7z",
        "rar",
        # Tool-specific outputs
        "hash",
        "hashes",
        "nessus",
        "nmap",
        "gnmap",
        "kdbx",
        "ovpn",
        "creds",
        "loot",
        "wordlist",
        # Images / media (occasionally come through)
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "ico",
    }
)


def _is_file_extension_tld(s: str) -> bool:
    """Return True if `s` has a final label matching a known file-extension
    TLD — i.e. it looks like `something.pcap`, not like a real hostname."""
    tail = s.rsplit(".", 1)
    if len(tail) != 2:
        return False
    return tail[1].lower() in _FILE_EXT_TLDS


def _looks_ip_or_network(s: str) -> bool:
    return bool(_RX_IPV4_SHAPE.match(s)) or bool(_RX_IPV6_SHAPE.match(s) and ":" in s)


def _looks_hostname(s: str) -> bool:
    if _is_file_extension_tld(s):
        return False
    return bool(_RX_HOSTNAME.match(s))


# ─── target normalization ──────────────────────────────────────────────────

_RX_IP_RANGE = re.compile(r"^(?P<base>\d{1,3}\.\d{1,3}\.\d{1,3}\.)(?P<lo>\d{1,3})-(?P<hi>\d{1,3})$")


def _looks_ip_range(token: str) -> bool:
    return bool(_RX_IP_RANGE.match((token or "").strip()))


def _expand_range_token(token: str, source_field: str) -> list[Target]:
    """Expand hyphenated IP ranges like `10.0.0.5-10` into individual
    Targets. Returns [] when the token isn't a range (caller should fall
    through to single-token classify). Used by cidr_list (which gets
    these from a range-style `--target 10.0.0.5-10` arg) and ip_or_host
    (single host/IP target).

    Refuses ranges with > 256 hosts to avoid pathological inputs blowing
    up the scope check. Range bounds are validated."""
    t = (token or "").strip()
    m = _RX_IP_RANGE.match(t)
    if not m:
        return [_classify_token(t, source_field=source_field)] if t else []
    base = m.group("base")
    lo = int(m.group("lo"))
    hi = int(m.group("hi"))
    if lo > hi or lo > 255 or hi > 255:
        raise ExtractorError(f"field {source_field!r} bad IP range {t!r}: bounds {lo}-{hi}")
    if hi - lo > 255:
        raise ExtractorError(
            f"field {source_field!r} range {t!r} exceeds /24 width — break it into smaller chunks"
        )
    out: list[Target] = []
    for i in range(lo, hi + 1):
        ip = f"{base}{i}"
        try:
            out.append(_classify_token(ip, source_field=source_field))
        except ExtractorError:
            pass
    if not out:
        raise ExtractorError(f"field {source_field!r} range {t!r} expanded to zero valid IPs")
    return out


def _classify_token(token: str, source_field: str) -> Target:
    """Decide whether `token` is an IP, network, host, or URL.

    Raises ExtractorError if the token is none of those.
    """
    t = (token or "").strip().rstrip(".")
    if not t:
        raise ExtractorError(f"empty value in field {source_field!r}")

    # SSH-style "[user@]host" — strip the user prefix when the token is
    # not a URL (URLs handle user info via urlparse below). Only one '@'
    # is treated as the SSH form to avoid mis-parsing pathological input.
    # Benefits ssh.* tools and other host-targeting shell commands.
    if "@" in t and t.count("@") == 1 and not t.lower().startswith(("http://", "https://")):
        user_part, host_part = t.split("@", 1)
        if user_part and host_part:
            t = host_part

    # URL? (http/https)
    if t.lower().startswith(("http://", "https://")):
        try:
            u = urllib.parse.urlparse(t)
        except ValueError as e:
            raise ExtractorError(f"unparseable URL in {source_field!r}: {e}") from e
        if not u.hostname:
            raise ExtractorError(f"URL in {source_field!r} has no host: {t!r}")
        # Reduce URL to its hostname for scope-check purposes.
        host = u.hostname.lower()
        return _classify_token(host, source_field)  # recurse to resolve ip vs host

    # IP / network shape?
    if _looks_ip_or_network(t):
        try:
            if "/" in t:
                net = ipaddress.ip_network(t, strict=False)
                return Target(kind="network", value=str(net), source_field=source_field)
            addr = ipaddress.ip_address(t)
            return Target(kind="ip", value=str(addr), source_field=source_field)
        except ValueError as e:
            raise ExtractorError(f"bad IP/network in {source_field!r}: {e}") from e

    # Hostname?
    if _looks_hostname(t):
        try:
            normalized = t.encode("idna").decode("ascii").lower()
        except UnicodeError:
            normalized = t.lower()
        return Target(kind="host", value=normalized, source_field=source_field)

    raise ExtractorError(
        f"unrecognized target {t!r} in field {source_field!r} — "
        f"expected IP, CIDR, hostname, or http(s) URL"
    )


def _classify_endpoint(token: str, source_field: str) -> Target:
    """Classify a connection endpoint that may carry a scheme and/or port,
    then reduce it to the host for the scope check.

    Handles the shapes the `protocol` tools pass: ``host:port`` (grpc/tls),
    ``ws://host:port/path`` / ``wss://…`` (websockets), ``[::1]:443``
    (bracketed IPv6), and a bare host/IP (mqtt broker, raw banner-grab).
    Any scheme is accepted — we only care about the host for scope. Raises
    ExtractorError if no host can be recovered."""
    t = (token or "").strip()
    if not t:
        raise ExtractorError(f"empty value in field {source_field!r}")
    # scheme://… (ws/wss/grpc/http/…) — let urlparse pull the hostname.
    if "://" in t:
        try:
            u = urllib.parse.urlparse(t)
        except ValueError as e:
            raise ExtractorError(f"unparseable endpoint in {source_field!r}: {e}") from e
        if not u.hostname:
            raise ExtractorError(f"endpoint in {source_field!r} has no host: {t!r}")
        return _classify_token(u.hostname, source_field)
    # Bracketed IPv6, optionally with a port: [::1] or [::1]:443.
    if t.startswith("["):
        host = t[1:].split("]", 1)[0]
        return _classify_token(host, source_field)
    # host:port — strip a single trailing numeric port. A bare IPv6
    # (e.g. ::1) has more than one colon and is left intact for the
    # IP classifier below.
    if t.count(":") == 1:
        host, _, port = t.partition(":")
        if host and port.isdigit():
            return _classify_token(host, source_field)
    return _classify_token(t, source_field)


# ─── extractors ────────────────────────────────────────────────────────────

ExtractorKind = Literal[
    "ip_or_host",
    "ip_optional",
    "host",
    "host_optional",
    "url",
    "url_or_host",
    "endpoint",
    "cidr_list",
    "raw_argv",
    "binary_argv",
    "wifi_bssid",
    "wifi_ssid",
    "wifi_bssid_optional",
    "wifi_ssid_optional",
    "local_only",
    "none",
]
"""Generic extractor kinds the kernel handles inline. Domain-specific kinds are
supplied by a downstream skin via `register_extractor` and travel as plain
strings in `ExtractorSpec.fields`, so that field is typed `str`, not this
Literal — the Literal is documentation for the kernel's own kinds."""


@dataclass(frozen=True)
class ExtractorSpec:
    """Per-tool declaration of where targets live in the args dict.

    `fields` maps arg-name → extractor kind. `local_only` is a shortcut
    for tools that don't network at all (the gate logs an allow + skips
    the check). `none` is for bus tools and others that should never be
    scope-checked.

    `at_least_one`: when True, every listed field is treated as optional;
    extract whatever's present. After all fields are processed, if zero
    targets were extracted, raise. Use when several alternative target
    fields could satisfy the tool — e.g. tools that accept
    either `domain` (host) or `target` (IP).

    `refuse_unparseable`: when True (default), raw_argv commands refuse
    commands with shell substitution, hex-encoded IPs, etc.
    """

    fields: Mapping[str, str] = field(default_factory=dict)
    local_only: bool = False
    none: bool = False
    at_least_one: bool = False
    refuse_unparseable: bool = True
    session_scoped: bool = False
    """When True, this is a relayed command surface (a downstream skin's
    established-session/agent relay) that runs THROUGH that session/agent.
    It is scope-checked ONLY when the engagement opts in via
    `scope.session_strict` (`ScopeStore.session_strict()`); otherwise the gate
    bypasses it like `none` (legacy established-session trust). When strict is
    on, the `session_command` extractor sweeps the command string for embedded
    out-of-scope targets (relay defense). See SC-1 / docs/SCOPE.md."""
    research: bool = False
    """When True, this tool is discovery/recon (it gathers public data, it does
    not act on the host). The gate checks its targets against the broad RESEARCH
    lane (`ScopeStore.check_research`) instead of the strict engagement scope:
    engagement-in-scope ∪ public-internet, minus a hard floor that always
    denies private/internal ranges + `out_targets`. Lets research agents reach
    public sites without a per-site `scope add`, while never widening the
    engagement scope. See `research_config_from_profile` + docs/SCOPE.md."""
    research_active: bool = False
    """When True (implies research), this research tool RESOLVES AND TOUCHES
    the target (active DNS query / probe / crawl). The public floor therefore
    fails CLOSED on a resolution failure: a host the daemon can't resolve
    can't be verified public, and an active tool might still reach it via a
    split-horizon resolver. Passive DB-lookup research tools
    (research=True, research_active=False) fail OPEN — they only ever query
    public databases, never the target itself."""

    def __post_init__(self) -> None:
        # Freeze `fields` so registered policy cannot change through a retained
        # caller reference or a nested mutation of `dataset.tool_targets[…].fields`
        # after `set_active()`. `dict(...)` decouples from the caller's original
        # mapping (blocks mutating the source dict); MappingProxyType makes the
        # stored copy read-only (blocks direct mutation of the registered spec).
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))

    def has_any_target_field(self) -> bool:
        return bool(self.fields)


# ─── extractor-kind registry (seam) ─────────────────────────────────────────
#
# The kernel implements a fixed set of GENERIC extractor kinds inline in
# `_extract_one` (ip_or_host, host, url, cidr_list, raw_argv, …). A downstream
# skin registers DOMAIN-SPECIFIC kinds (its own tool grammars) via
# `register_extractor`, consulted at call time. Generic kinds are reserved: a
# skin cannot shadow one. A kind that is neither inline nor registered raises
# the same ExtractorError as before (`unknown extractor kind: …`) — the public
# kernel's behavior for a kind no skin has installed.

SCOPE_API_VERSION = 1
"""Bumped when the extractor facade (ExtractorCtx + exported helpers) changes
in a way a skin must adapt to. A skin asserts compatibility at startup."""


@dataclass(frozen=True)
class ExtractorCtx:
    """What a registered (skin) extractor receives. `raw` is `args.get(field)`
    already fetched; the extractor reads any additional sibling fields it needs
    straight from `args` (e.g. a registered extractor may read a sibling field
    and args['options'])."""

    args: dict[str, Any]
    field: str
    optional: bool
    raw: Any


Extractor = Callable[["ExtractorCtx"], list[Target]]

# Kinds handled inline by `_extract_one` — reserved; a skin may not register
# these. Derived from the ExtractorKind Literal so it narrows automatically as
# domain-specific kinds are removed from the kernel.
_CORE_KINDS: frozenset[str] = frozenset(get_args(ExtractorKind))

_EXTRACTORS: dict[str, Extractor] = {}


def register_extractor(kind: str, fn: Extractor, *, override: bool = False) -> None:
    """Register a downstream extractor kind. Rejects reserved core kinds and
    silent duplicates — clobbering an extractor on a scope boundary is a
    regression, not a convenience. Pass override=True to intentionally replace."""
    if kind in _CORE_KINDS:
        raise ExtractorError(f"cannot register reserved core extractor kind: {kind!r}")
    if kind in _EXTRACTORS and not override:
        raise ExtractorError(f"extractor kind already registered: {kind!r}")
    _EXTRACTORS[kind] = fn


def unregister_all_extractors() -> None:
    """Clear the registry. Test-only — call between tests so a registration in
    one test can't leak into another."""
    _EXTRACTORS.clear()


# obfuscation indicators that refuse_unparseable=True should refuse on.
#
# `\xNN` / `0xHEXHEX…` patterns only refuse when long enough to plausibly
# encode an IP — a 4-byte IPv4 IP needs 8 hex digits (e.g. 0x0a000005 =
# 10.0.0.5). Shorter forms like `\x00`, `\xff` are common in legitimate
# byte-level work (shellcode generation, writing null terminators) and
# refusing them blocks legitimate binary output dumps or python `b'\x00'`
# string. The 4-byte threshold (8 hex digits) catches the obfuscation pattern
# without the false positives.
_RX_OBFUSCATION = re.compile(
    r"\$\(|`|<\(|>\(|"
    r"(?:\\x[0-9a-f]{2}){4,}|"  # 4+ consecutive \xNN bytes (IP-shaped)
    r"0x[0-9a-f]{8,}|"  # decimal-or-hex IP encoding (≥8 hex digits)
    r"\$\{[a-z_][a-z_0-9]*\}|\$[a-z_][a-z_0-9]*",
    re.IGNORECASE,
)
# In a raw_argv context, env-var refs are only OK if the var was set in
# the same invocation: `RHOST=10.0.0.5 nmap $RHOST`. Cheap detect: if every
# $VAR in the string has a matching VAR=... earlier in the string, allow.
_RX_ENVSET = re.compile(r"^([A-Z_][A-Z_0-9]*)=", re.IGNORECASE)
_RX_ENVREF = re.compile(r"\$\{?([A-Z_][A-Z_0-9]*)\}?", re.IGNORECASE)

# ── encoded-payload execution ────────────────────────────────────────────────
# A decode/transform wrapper that turns an opaque blob back into runnable
# text/bytes. On its own this is harmless (`base64 -d blob > out.bin`); it only
# hides a target when its output is fed to a dynamic-exec sink (below).
_RX_DECODE_WRAPPER = re.compile(
    r"\bb64decode\b|\bbase64\b\s*(?:\.\w+|-d\b|--decode\b)|"
    r"\bunhexlify\b|\bfromhex\b|"
    r"\bcodecs\.(?:decode|getdecoder)\b|"
    r"rot[_-]?13",
    re.IGNORECASE,
)
# A sink that runs decoded text/bytes as code. `exec`/`eval`/`os.system`/
# `subprocess`/`Popen` and shell `| sh` / `sh -c` are the common ones.
_RX_EXEC_SINK = re.compile(
    r"\bexec\s*\(|\beval\s*\(|\bexecfile\b|\bos\.system\b|\bsubprocess\b|"
    r"\bPopen\b|\bcheck_output\b|\bcheck_call\b|"
    r"\|\s*(?:ba)?sh\b|\b(?:ba)?sh\s+-c\b",
    re.IGNORECASE,
)
# An address reassembled from adjacent quoted fragments joined by `+`
# (`'1'+'0.'+'0.'+'0.'+'5'`) never presents a contiguous dotted-quad/IPv6 to the
# token sweep. Require a `.` or `:` inside at least one of the two joined
# fragments so plain word concatenation (`'a'+'b'`) is not refused.
_RX_SPLICED_ADDRESS = re.compile(
    r"""['"][0-9a-f]*[.:][0-9a-f.:]*['"]\s*\+\s*['"][0-9a-f.:]*['"]"""
    r"""|['"][0-9a-f.:]*['"]\s*\+\s*['"][0-9a-f]*[.:][0-9a-f.:]*['"]""",
    re.IGNORECASE,
)


def _encoded_exec_obfuscation(text: str) -> str | None:
    """Refuse a decode/transform wrapper whose output feeds a dynamic-exec sink
    (e.g. `python -c "exec(base64.b64decode('…'))"`, `base64 -d blob | sh`,
    `codecs.decode(x,'rot13')` into `exec`). The decoded payload never reaches
    the token sweep, so the real target is invisible to scope. Requiring BOTH a
    wrapper AND a sink keeps false positives bounded — a lone decoder that writes
    to a file, or a lone `subprocess` call with no encoding, is left alone."""
    if _RX_DECODE_WRAPPER.search(text) and _RX_EXEC_SINK.search(text):
        return "encoded payload fed to a dynamic-exec sink"
    return None


_RX_IPV4_TOKEN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_RX_URL_TOKEN = re.compile(r"https?://[^\s'\"`<>|;&]+", re.IGNORECASE)
# IPv6 CANDIDATE token: 2+ colon-separated hex groups (so a single-colon
# `host:port` or a `12:00` time never matches), optional `::` compression,
# optional `%zone` id, optional `/prefix`. This is deliberately loose — real
# validation is `ipaddress.ip_address` inside `_classify_token`, which drops
# any candidate that isn't a genuine IPv6 address (the sweep swallows the
# ExtractorError). Without this, an IPv6 target in a raw_argv command extracts
# nothing → the scope gate never checks it (only an IPv4 regex existed before).
# Boundaries exclude ALL word chars (not just hex) so a scope-resolution token
# like `sekurlsa::logonpasswords` or `Foo::Bar` — `word::word`, which looks like
# compressed IPv6 — is not matched mid-identifier. A real address is preceded by
# whitespace / `[` / `=` / `@` / quote, all non-word.
_RX_IPV6_TOKEN = re.compile(
    r"(?<![\w:%.])"
    r"(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}"
    r"(?:%[0-9a-z_.-]+)?"
    r"(?:/\d{1,3})?"
    r"(?![\w:%.])",
    re.IGNORECASE,
)
# Boundary assertions:
#   (?<!\\)  — refuse matches preceded by a literal backslash, so `\n`, `\t`,
#              `\x`, `\u` escapes inside python/JSON string literals don't
#              eat the escape char as part of the hostname (live false
#              positive 2026-05-13: `\nsubprocess.call` was parsed as host
#              `nsubprocess.call`).
#   (?!\()   — refuse matches immediately followed by `(`, which always
#              signals a method/function call (`s.fileno()`, `os.path.join(`),
#              never a real hostname-in-command.
_RX_HOST_TOKEN = re.compile(
    r"(?<!\\)\b(?![\d])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b(?!\()",
    re.IGNORECASE,
)


# Labels that the host regex catches but that are almost never real DNS
# TLDs in command-line contexts — file extensions, Python attribute names,
# common method calls. Real DNS hostnames end in a registered TLD;
# `mine.sh`, `os.environ`, `t.connect`, `walk.py` all look hostname-shaped
# to the regex but are local scripts / Python code.
#
# This filter ONLY applies to the opportunistic regex sweep inside raw_argv
# /binary_argv. Explicit target fields (a tool's explicit target=/url=
# url=) are not affected — operators who scope `mine.sh` deliberately
# still get the explicit-field path.
_NOT_A_REAL_TLD: frozenset[str] = frozenset(
    {
        # ── file extensions ────────────────────────────────────────────────
        "py",
        "sh",
        "bash",
        "zsh",
        "fish",
        "ps1",
        "psm1",
        "psd1",
        "bat",
        "cmd",
        "txt",
        "md",
        "rst",
        "json",
        "yml",
        "yaml",
        "toml",
        "cfg",
        "ini",
        "log",
        "env",
        "lock",
        "bak",
        "swp",
        "swo",
        "swn",
        "tmp",
        "sock",
        "pid",
        "key",
        "crt",
        "pem",
        "csr",
        "cer",
        "p12",
        "pfx",
        "conf",
        "service",
        "target",
        "timer",
        "socket",
        "html",
        "htm",
        "css",
        "js",
        "jsx",
        "ts",
        "tsx",
        "mjs",
        "cjs",
        "c",
        "cpp",
        "cc",
        "cxx",
        "h",
        "hpp",
        "hxx",
        "java",
        "rb",
        "php",
        "go",
        "rs",
        "lua",
        "sql",
        "db",
        "sqlite",
        "sqlite3",
        "dbf",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "svg",
        "ico",
        "bmp",
        "webp",
        "tiff",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "ods",
        "odp",
        "zip",
        "tar",
        "gz",
        "bz2",
        "xz",
        "7z",
        "rar",
        "tgz",
        "tbz",
        "tlz",
        "lzma",
        "zst",
        "exe",
        "dll",
        "so",
        "dylib",
        "out",
        "bin",
        "deb",
        "rpm",
        "pkg",
        "dmg",
        "iso",
        "img",
        "vhd",
        "vmdk",
        "qcow2",
        "ova",
        "ovf",
        "mp3",
        "mp4",
        "wav",
        "avi",
        "mov",
        "mkv",
        "flac",
        "ogg",
        "m4a",
        "webm",
        "whl",
        "egg",
        "jar",
        "war",
        "ear",
        "class",
        "ko",
        "mod",
        "map",
        "sym",
        # ── Python / shell attribute + method names commonly dotted in code
        "write",
        "read",
        "close",
        "open",
        "connect",
        "send",
        "recv",
        "accept",
        "bind",
        "listen",
        "shutdown",
        "get",
        "set",
        "put",
        "post",
        "delete",
        "update",
        "insert",
        "remove",
        "clear",
        "append",
        "extend",
        "pop",
        "push",
        "shift",
        "unshift",
        "slice",
        "splice",
        "join",
        "split",
        "replace",
        "sub",
        "match",
        "search",
        "find",
        "filter",
        "reduce",
        "sorted",
        "reversed",
        "each",
        "keys",
        "values",
        "items",
        "environ",
        "stdout",
        "stderr",
        "stdin",
        "argv",
        "path",
        "getenv",
        "setenv",
        "transport",
        "filemode",
        "rstrip",
        "lstrip",
        "strip",
        "casefold",
        "format",
        "dumps",
        "loads",
        "dump",
        "load",
        "decode",
        "encode",
        "pack",
        "unpack",
        "sftpclient",
        "sftpattributes",
        "filename",
        "name",
        "title",
        "exists",
        "mkdir",
        "makedirs",
        "rmdir",
        "unlink",
        "walk",
        "listdir",
        "scandir",
        "isfile",
        "isdir",
        "abspath",
        "dirname",
        "basename",
        "splitext",
        "realpath",
        "relpath",
        "commonpath",
        "getuid",
        "geteuid",
        "getpid",
        "getppid",
        "getgid",
        "getegid",
        "cwd",
        "getcwd",
        "chdir",
        "system",
        "popen",
        "fork",
        "exec",
        "execv",
        "execve",
        "execvp",
        "fileno",
        "call",
        "check_call",
        "check_output",
        "run",
        "communicate",
        "meta",  # Splunk app metadata (default.meta, local.meta)
        "time",
        "sleep",
        "monotonic",
        "gmtime",
        "localtime",
        "strftime",
        "strptime",
        "lower",
        "upper",
        "capitalize",
        "center",
        "ljust",
        "rjust",
        # ── Python imaging / data-science attribute names ──────────────────
        # Hit live 2026-05-12: agent ran a PIL script, scope flagged
        # `pil.exiftags`, `img.size`, `img.mode` as out-of-scope hostnames.
        "size",
        "mode",
        "exif",
        "exiftags",
        "tags",
        "shape",
        "dtype",
        "ndim",
        "itemsize",
        "nbytes",
        "index",
        "columns",
        "axes",
        "info",
        "palette",
        "getexif",
        "getdata",
        "thumbnail",
        "crop",
        "rotate",
        "transpose",
        "histogram",
        # Common pandas / numpy method-suffixes
        "iloc",
        "loc",
        "iat",
        "at",
        "iterrows",
        "itertuples",
        "tolist",
        # Pillow / PIL module names that show up dotted
        "image",
        "imagedraw",
        "imagefont",
        "imageops",
    }
)


def _is_real_hostname_shape(token: str, extra: frozenset[str] = frozenset()) -> bool:
    """Return False for tokens that look hostname-shaped to the regex but
    are almost certainly Python attribute access (`os.environ`) or file
    extensions (`mine.sh`, `walk.py`). Used to filter the regex sweep
    inside raw_argv / binary_argv extraction.

    Heuristics:
      - Last label not in _NOT_A_REAL_TLD
      - Last label is 2+ alphabetic chars (no all-numeric/short TLDs)

    Filtering is conservative: explicit-field extraction (nmap target=,
    ffuf url=) bypasses this entirely. Operators who scope a `.sh` domain
    use that explicit path."""
    parts = token.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return False
    last = parts[-1]
    if last in _NOT_A_REAL_TLD or last in extra:
        return False
    if len(last) < 2 or not last.isalpha():
        return False
    return True


def _sweep_tokens(
    text: str,
    field: str,
    *,
    extra_not_tld: frozenset[str] = frozenset(),
) -> list[Target]:
    """Opportunistic URL/IP/host regex sweep over free-form command text.

    Used by raw_argv (and skin-registered command extractors): URLs first (their spans
    masked so an embedded host isn't double-reported), then IPv4 tokens, then
    hostname-shaped tokens that survive `_is_real_hostname_shape`. Tokens that
    fail classification are skipped (not every hostname-shaped token is a real
    target). `extra_not_tld` adds caller-specific labels to the host filter."""
    targets: list[Target] = []
    seen_spans: list[tuple[int, int]] = []
    for m in _RX_URL_TOKEN.finditer(text):
        try:
            targets.append(_classify_token(m.group(0), source_field=field))
            seen_spans.append((m.start(), m.end()))
        except ExtractorError:
            pass
    for m in _RX_IPV4_TOKEN.finditer(text):
        if _overlaps(m.start(), m.end(), seen_spans):
            continue
        tok = m.group(0)
        # A dotted-quad with a zero-padded octet (012.0.0.5) is octal IP
        # obfuscation — refuse loudly rather than silently drop it (it would
        # otherwise fail strict IP parse and be swallowed, leaving the command
        # target-less -> allowed).
        if _has_leading_zero_octet(tok):
            raise ExtractorError(
                f"octal-encoded IP {tok!r} (leading-zero octet; inet_aton "
                f"reads it as octal). Use canonical dotted notation."
            )
        try:
            targets.append(_classify_token(tok, source_field=field))
            seen_spans.append((m.start(), m.end()))
        except ExtractorError:
            pass
    for m in _RX_IPV6_TOKEN.finditer(text):
        if _overlaps(m.start(), m.end(), seen_spans):
            continue
        # Drop a `%zone` scope-id (`fe80::1%eth0`) before classifying: it's
        # irrelevant to the scope check and `_classify_token`'s shape gate
        # rejects the `%`, which would otherwise let a zoned address slip
        # through as an unrecognized (→ unchecked) token.
        cand = m.group(0).split("%", 1)[0]
        # A colon-only match (`::`, `:::`) is the unspecified/loopback shorthand
        # with no hextet — skip it rather than mint a spurious `::` target from a
        # stray double-colon in prose/code.
        if not any(c in "0123456789abcdefABCDEF" for c in cand):
            continue
        try:
            # `_classify_token` runs `ipaddress.ip_address`, so a candidate that
            # isn't a real IPv6 address (`12:00:00`, `a:b:c`) raises and is
            # skipped here — only genuine addresses become scope-checked targets.
            targets.append(_classify_token(cand, source_field=field))
            seen_spans.append((m.start(), m.end()))
        except ExtractorError:
            pass
    for m in _RX_HOST_TOKEN.finditer(text):
        if _overlaps(m.start(), m.end(), seen_spans):
            continue
        tok = m.group(0)
        if not _is_real_hostname_shape(tok, extra_not_tld):
            continue
        try:
            targets.append(_classify_token(tok, source_field=field))
            seen_spans.append((m.start(), m.end()))
        except ExtractorError:
            pass
    return targets


def _is_locally_bound(var_name: str, text_before: str) -> bool:
    """True if `$VAR` was bound earlier in the same command string.
    Covers the common bash idioms operators actually use:
        VAR=value …
        for VAR in …; do
        while read VAR
        read -r VAR
        select VAR in …
        getopts ... VAR
    Without these, my earlier "VAR=" check would refuse every legitimate
    bash one-liner that loops over files (`for f in *.txt; do … $f …`)."""
    n = re.escape(var_name)
    patterns = (
        rf"\b{n}\s*=",  # NAME=value
        rf"\bfor\s+{n}\s+in\b",  # for f in …
        rf"\bread\s+(?:-\w+\s+)*(?:[A-Za-z_][\w]*\s+)*{n}\b",  # read … f
        rf"\bselect\s+{n}\s+in\b",  # select f in …
        rf"\bgetopts\s+\S+\s+{n}\b",  # getopts spec f
    )
    return any(re.search(p, text_before) for p in patterns)


# A standalone run of 8-10 digits — the width of a 32-bit integer (2**24 =
# 16777216 is 8 digits, 2**32-1 = 4294967295 is 10). Bounded by non-word,
# non-dot so it never fires inside `0x0a000005`, a dotted-quad octet, or a
# longer identifier. Range is checked in code (regex can't compare magnitude).
_RX_BARE_INT = re.compile(r"(?<![\w.])(\d{8,10})(?![\w.])")


def _bare_int_ip_encoding(text: str) -> str | None:
    """Refuse a standalone integer that inet_aton would read as a full IPv4
    address (>= 2**24, so the high byte is non-zero — e.g. 167772165 = 10.0.0.5).

    Unlike `0x…` hex, a bare integer carries no explicit encoding signal, so we
    can't tell "encoded target" from "large count/timestamp" — and this only
    runs in the raw_argv obfuscation path, where a target-bearing command that
    names an integer-encoded host would otherwise slip the scope gate entirely
    (empty extraction -> allowed). Fail closed: the operator restates a real
    target in dotted notation. Values < 2**24 (ports, small counts) are left
    alone; dotted forms are handled by the IPv4 sweep."""
    for m in _RX_BARE_INT.finditer(text):
        val = int(m.group(1))
        if (1 << 24) <= val < (1 << 32):
            dotted = ipaddress.ip_address(val)
            return (
                f"integer-encoded IP {m.group(1)} (inet_aton reads it as "
                f"{dotted}). Use canonical dotted notation ({dotted}) so the "
                f"scope gate can check the target."
            )
    return None


def _has_leading_zero_octet(token: str) -> bool:
    """True if a dotted-quad-shaped token has a zero-padded octet (012.0.0.5).
    inet_aton reads a leading-zero octet as OCTAL (012 -> 10), so this is IP
    obfuscation; no legitimate address zero-pads its octets."""
    host = token.split("/", 1)[0]
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return any(len(p) > 1 and p[0] == "0" for p in parts)


def _is_obfuscated(text: str) -> str | None:
    """Return a description if the text contains obfuscation we refuse, else None."""
    # Bare integer-encoded IPs carry no `0x`-style signal the regex can anchor
    # on, so check them independently of (and before) the pattern sweep.
    bare = _bare_int_ip_encoding(text)
    if bare:
        return bare
    enc = _encoded_exec_obfuscation(text)
    if enc:
        return enc
    if _RX_SPLICED_ADDRESS.search(text):
        return "address spliced across adjacent string literals"
    m = _RX_OBFUSCATION.search(text)
    if not m:
        return None
    matched = m.group(0)
    # Allow env-var refs that are locally set in the same invocation.
    if matched.startswith("$"):
        var = _RX_ENVREF.match(matched)
        if var:
            name = var.group(1)
            if _is_locally_bound(name, text[: m.start()]):
                # Locally bound — try the next obfuscation match (recurse cheap).
                rest = text[m.end() :]
                inner = _is_obfuscated(rest)
                return inner
            return (
                f"reference to non-local env var ${name} (each bash.run "
                f"starts a fresh `bash -c` — variables from a prior call "
                f"don't carry. Inline the value (`curl 10.0.0.5`) OR "
                f"set+use in ONE command (`{name}=10.0.0.5 && curl "
                f"${name}`))"
            )
    if matched == "`" or matched == "$(":
        return "command substitution"
    if matched.startswith(("<(", ">(")):
        return "process substitution"
    if matched.startswith(("\\x", "0x")):
        return f"hex-encoded byte/IP ({matched})"
    return f"refused construct: {matched!r}"


def _extract_one(
    args: dict[str, Any],
    field: str,
    kind: str,
    optional: bool = False,
) -> list[Target]:
    """Extract Target(s) for a single arg-field according to its kind.

    `optional`: when True, missing/empty values return [] instead of raising.
    Malformed values STILL raise even when optional — missing-field is OK,
    bad-data is not."""
    raw = args.get(field)

    if kind in ("ip_optional", "host_optional"):
        if raw in (None, "", []):
            return []
        kind = "ip_or_host" if kind == "ip_optional" else "host"  # fall through

    if kind in ("wifi_bssid_optional", "wifi_ssid_optional"):
        if raw in (None, "", []):
            return []
        kind = "wifi_bssid" if kind == "wifi_bssid_optional" else "wifi_ssid"

    # Domain-specific kinds a downstream skin registered — consulted BEFORE the
    # generic empty-guard so the extractor owns its own missing/empty semantics
    # (e.g. a relayed session command that names nothing is allowed, not
    # refused). A miss falls through to the kernel's inline generic handling.
    fn = _EXTRACTORS.get(kind)
    if fn is not None:
        return fn(ExtractorCtx(args=args, field=field, optional=optional, raw=raw))

    if raw in (None, "", []):
        if optional:
            return []
        raise ExtractorError(f"required field {field!r} is missing/empty")

    if kind == "wifi_bssid":
        token = str(raw).strip()
        try:
            value = _normalize_bssid(token)
        except ValueError as e:
            raise ExtractorError(f"field {field!r}: {e}") from e
        return [Target(kind="wifi_bssid", value=value, source_field=field)]

    if kind == "wifi_ssid":
        token = str(raw).strip()
        if not token:
            raise ExtractorError(f"field {field!r} expects an SSID, got empty")
        if len(token.encode("utf-8")) > 32:
            raise ExtractorError(f"field {field!r} SSID {token!r} exceeds 32 bytes")
        return [Target(kind="wifi_ssid", value=token, source_field=field)]

    if kind in ("ip_or_host", "host"):
        token = str(raw).strip()
        if kind == "ip_or_host" and _looks_ip_range(token):
            ts = _expand_range_token(token, source_field=field)
            if ts:
                return ts
        t = _classify_token(token, source_field=field)
        if kind == "host" and t.kind != "host":
            raise ExtractorError(f"field {field!r} expects a hostname, got {t.kind} {t.value!r}")
        if kind == "ip_or_host" and t.kind not in ("ip", "host", "network"):
            raise ExtractorError(f"field {field!r} expects ip/host, got {t.kind} {t.value!r}")
        return [t]

    if kind == "url":
        token = str(raw).strip()
        if not token.lower().startswith(("http://", "https://")):
            raise ExtractorError(f"field {field!r} expects a URL, got {token!r}")
        return [_classify_token(token, source_field=field)]

    if kind == "url_or_host":
        token = str(raw).strip()
        return [_classify_token(token, source_field=field)]

    if kind == "endpoint":
        return [_classify_endpoint(str(raw).strip(), source_field=field)]

    if kind == "cidr_list":
        if isinstance(raw, str):
            tokens = re.split(r"[,\s]+", raw.strip())
        elif isinstance(raw, list):
            tokens = [str(t).strip() for t in raw]
        else:
            raise ExtractorError(
                f"field {field!r} expects a list/string of CIDRs, got {type(raw).__name__}"
            )
        tokens = [t for t in tokens if t]
        if not tokens:
            raise ExtractorError(f"field {field!r} is empty after parsing")
        out: list[Target] = []
        for cidr in tokens:
            out.extend(_expand_range_token(cidr, source_field=field))
        return out

    if kind == "binary_argv":
        # The 11 agents whose `run` takes `binary: str` + `args: list` (not
        # `command: str`) — synthesize a single shell-style command line
        # from those two fields and parse it the same way as raw_argv.
        # `field` for binary_argv is conventionally "binary" — we ignore
        # raw and read both `binary` and `args` straight from the args dict.
        binary = str(args.get("binary") or "").strip()
        arglist = args.get("args")
        if arglist in (None, ""):
            arglist = []
        if not isinstance(arglist, list):
            raise ExtractorError(
                f"binary_argv: 'args' must be a list, got {type(arglist).__name__}"
            )
        joined = " ".join([binary] + [str(a) for a in arglist if str(a)]).strip()
        if not joined:
            if optional:
                return []
            raise ExtractorError("binary_argv: both 'binary' and 'args' are empty")
        # Re-enter the raw_argv branch with the synthesized string.
        return _extract_one(
            {"_argv_text": joined},
            "_argv_text",
            "raw_argv",
            optional=optional,
        )

    if kind == "raw_argv":
        # Tool may pass either a single string (`bash.run.command`) or a
        # list of strings. For lists, join with newlines so the regex sweep +
        # obfuscation detector see the whole multi-line script.
        if isinstance(raw, list):
            text = "\n".join(str(t) for t in raw if str(t).strip())
        else:
            text = str(raw)
        # Collapse Unicode compatibility forms (full-width / homoglyph digits and
        # letters) to their ASCII equivalents BEFORE detection + sweep, so an
        # address written with fancy digits (`１０.０.０.５`, `𝟣𝟢.𝟢.𝟢.𝟧`) reduces to
        # `10.0.0.5` and is caught by the same IPv4 / integer / host detectors as
        # its plain-ASCII spelling. Detection-only: the executed command is never
        # touched — we only inspect this normalized copy for scope-check purposes.
        text = unicodedata.normalize("NFKC", text)
        if not text.strip():
            if optional:
                return []
            raise ExtractorError(f"field {field!r} is empty after joining list elements")

        obf = _is_obfuscated(text)
        if obf:
            raise ExtractorError(
                f"refused: {field!r} contains {obf}. Set this command's "
                f"targets in flat form (e.g. `curl 10.0.0.5`, no $(), no "
                f"variable indirection, no hex-encoded IPs) and try again."
            )

        # URLs first (their spans masked internally so an embedded host isn't
        # double-reported), then IPs, then hostname-shaped tokens that survive
        # `_is_real_hostname_shape` (filters `os.environ`, `mine.sh`, etc.).
        targets: list[Target] = _sweep_tokens(text, field)
        if not targets:
            # No remote target named. The scope contract is "IF a command names
            # a target, that target must be in scope" — not "every command must
            # name one" (`ls /tmp`, `jobs -l`). A flat command that goes on the
            # wire would have produced an IP/host/URL token and been checked.
            #
            # BEST-EFFORT, NOT AUTHORITATIVE. This is a static regex sweep over
            # free-form shell/Python, so it is deliberately one layer of
            # defense-in-depth, not a sealed boundary. The obfuscation detector
            # above fails CLOSED on the evasions it recognizes (substitution,
            # encoded IPs, unbound $VARs, decode→exec, spliced literals), but a
            # sufficiently determined command can still name a target the sweep
            # can't see (runtime-computed strings, novel encodings, multi-call
            # /tmp indirection). Those are the message-bus + operator-approval
            # layers' job to catch — NOT a guarantee this function makes. Route
            # target-bearing work through the typed tool factories (nmap, ssh,
            # …) wherever possible rather than `*.run` shell escapes.
            return []
        return targets

    if kind == "none":
        return []

    raise ExtractorError(f"unknown extractor kind: {kind!r}")


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    for s, e in spans:
        if start < e and s < end:
            return True
    return False


def extract_targets(spec: ExtractorSpec, args: dict[str, Any]) -> list[Target]:
    """Top-level: given a spec and the tool's call args, return the targets.

    Returns [] for `none` or `local_only` specs (the gate handles them
    separately). Raises ExtractorError if any field can't be parsed.

    When spec.at_least_one is True, individually missing/empty fields are
    skipped (instead of raising), but at the end we require at least one
    target overall — otherwise refuse with a clear error message.
    """
    if spec.none or spec.local_only:
        return []
    out: list[Target] = []
    for field_name, kind in spec.fields.items():
        out.extend(
            _extract_one(
                args,
                field_name,
                kind,
                optional=spec.at_least_one,
            )
        )
    if spec.at_least_one and spec.fields and not out:
        raise ExtractorError(
            f"none of {list(spec.fields)} were set — at least one target "
            f"field is required; got args: {sorted(args)}"
        )
    return out


# ─── the store ─────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS scope_rules (
    pattern       TEXT    NOT NULL,
    kind          TEXT    NOT NULL,
    direction     TEXT    NOT NULL,
    origin        TEXT    NOT NULL,
    added_by      TEXT    NOT NULL,
    added_at      REAL    NOT NULL,
    expires_at    REAL,
    one_shot      INTEGER NOT NULL DEFAULT 0,
    consumed_at   REAL,
    reason        TEXT    NOT NULL,
    PRIMARY KEY (pattern, direction, origin)
);

CREATE TABLE IF NOT EXISTS scope_decisions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL    NOT NULL,
    engagement_id TEXT    NOT NULL,
    agent         TEXT    NOT NULL,
    tool          TEXT    NOT NULL,
    args_json     TEXT    NOT NULL,
    targets_json  TEXT    NOT NULL,
    verdict       TEXT    NOT NULL,
    matched_rule  TEXT,
    reason        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS scope_decisions_ts          ON scope_decisions(ts);
CREATE INDEX IF NOT EXISTS scope_decisions_verdict     ON scope_decisions(verdict);
CREATE INDEX IF NOT EXISTS scope_decisions_engagement  ON scope_decisions(engagement_id);
"""


# ─── operator-side IP detection ─────────────────────────────────────────────
#
# Any IPv4/IPv6 address assigned to a local NIC is, by definition, this box
# — i.e. the operator's own infrastructure. Such addresses commonly surface
# as LHOST / callback hosts inside payload source, curl command lines, or
# config files. They are never engagement targets, so the scope gate filters
# them out before evaluating rules. Cache the lookup so we don't fork `ip`
# on every tool call; refresh on a short TTL so a tun0 brought up mid-session
# starts getting exempted within a minute.

_LOCAL_ADDR_TTL = 60.0
_local_addr_cache: tuple[float, frozenset[Any]] | None = None


def _local_addresses() -> frozenset[Any]:
    """Frozen set of `ipaddress.ip_address` objects bound to local NICs.

    Reads `ip -j addr show`. If iproute2 is unavailable or returns
    unparseable output we fall back to {127.0.0.1, ::1} — degrading to a
    minimal exemption set rather than silently exempting everything.
    """
    global _local_addr_cache
    now = time.monotonic()
    if _local_addr_cache is not None:
        ts, cached = _local_addr_cache
        if now - ts < _LOCAL_ADDR_TTL:
            return cached
    addrs: set[Any] = set()
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=True,
        )
        data = json.loads(proc.stdout or "[]")
        for iface in data:
            for info in iface.get("addr_info") or []:
                local = info.get("local")
                if not local:
                    continue
                try:
                    addrs.add(ipaddress.ip_address(local))
                except ValueError:
                    continue
    except (subprocess.SubprocessError, FileNotFoundError, json.JSONDecodeError, OSError):
        addrs.update(
            {
                ipaddress.ip_address("127.0.0.1"),
                ipaddress.ip_address("::1"),
            }
        )
    if not addrs:
        addrs.update(
            {
                ipaddress.ip_address("127.0.0.1"),
                ipaddress.ip_address("::1"),
            }
        )
    frozen = frozenset(addrs)
    _local_addr_cache = (now, frozen)
    return frozen


def _is_operator_target(t: Target) -> bool:
    """True iff `t` is an IPv4/IPv6 address assigned to this host."""
    if t.kind != "ip":
        return False
    try:
        addr = ipaddress.ip_address(t.value)
    except ValueError:
        return False
    return addr in _local_addresses()


def _split_operator_targets(
    targets: list[Target],
) -> tuple[list[Target], list[Target]]:
    """Partition into (remote_targets, operator_side_targets)."""
    remote: list[Target] = []
    op: list[Target] = []
    for t in targets:
        (op if _is_operator_target(t) else remote).append(t)
    return remote, op


def _operator_filter_note(op_targets: list[Target]) -> str:
    """Comma-joined IP values for the filtered operator-side targets."""
    return ", ".join(sorted({t.value for t in op_targets}))


# ─── research lane (public-web access, separate from engagement scope) ────────
#
# The research lane lets discovery/recon tools (ExtractorSpec.research=True) reach
# the PUBLIC internet without a per-site `scope add`, while NEVER widening the
# engagement's scope. It is strictly ADDITIVE: a target is allowed iff it
# is already in engagement scope OR it passes the public floor below. The floor
# is the load-bearing safety invariant — research tools can never reach
# private/internal infra or `out_targets`.

_DEFAULT_INTERNAL_TLDS: tuple[str, ...] = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".intranet",
    ".home.arpa",
)
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 shared space


@dataclass(frozen=True)
class ResearchPolicy:
    """Per-engagement research-lane policy, parsed from
    `profile["scope"]["research"]`. Default is `public` (on) — the lane is
    on-by-default; set `mode: off` to revert research tools to strict scope."""

    mode: str = "public"  # public | allowlist | off
    in_rules: tuple[ScopeRule, ...] = ()  # allowlist-mode patterns
    internal_tlds: tuple[str, ...] = _DEFAULT_INTERNAL_TLDS


def _norm_tld(x: str) -> str:
    s = str(x).strip().lower().rstrip(".")
    return s if s.startswith(".") else "." + s


def research_config_from_profile(profile: dict[str, Any] | None) -> ResearchPolicy:
    """Read the research lane policy from the engagement profile's
    `scope.research` block. Mirrors `safeguards.posture_from_profile`. Absent
    block → default `public` (on). `scope.research: off` (or `false`, or
    `{mode: off}`) → research tools fall back to strict engagement scope."""
    scope_block = (profile or {}).get("scope") or {}
    rb = scope_block.get("research")
    if rb is None:
        return ResearchPolicy()
    if rb is False or (isinstance(rb, str) and rb.strip().lower() == "off"):
        return ResearchPolicy(mode="off")
    if not isinstance(rb, dict):
        return ResearchPolicy()
    mode = str(rb.get("mode") or "public").strip().lower()
    if mode not in ("public", "allowlist", "off"):
        mode = "public"
    in_rules: list[ScopeRule] = []
    now = time.time()
    for pat in _as_list(_coalesce(rb, "in", "in_targets") or []):
        try:
            kind, norm = parse_rule(pat)
        except ValueError:
            continue
        in_rules.append(
            ScopeRule(
                pattern=norm,
                kind=kind,
                direction="in",
                origin="engagement",
                added_by="engagement.yaml:scope.research",
                added_at=now,
                reason="",
            )
        )
    # internal_tlds EXTENDS the built-in floor — it can only ADD names, never
    # remove a default. Otherwise an operator setting `internal_tlds: [.corp]`
    # would silently drop `.internal` (GCP/cloud metadata) + `.home.arpa`,
    # re-opening them to the lane. The floor only ever tightens.
    extra = tuple(_norm_tld(x) for x in _as_list(rb.get("internal_tlds") or []))
    tlds = _DEFAULT_INTERNAL_TLDS + tuple(t for t in extra if t not in _DEFAULT_INTERNAL_TLDS)
    return ResearchPolicy(mode=mode, in_rules=tuple(in_rules), internal_tlds=tlds)


# Resolver indirection so tests can monkeypatch `_resolve_host` for
# determinism (no real DNS). Results are cached with a short TTL. The cache is
# process-global (one ScopeStore per daemon); the public/private verdict is
# recomputed per call from the (re-resolved, TTL-refreshed) addrs, so a shared
# cache only saves lookups — it never carries a verdict across engagements.
_RESOLVE_TTL = 300.0
_RESOLVE_CACHE_MAX = 5000
_resolve_cache: dict[str, tuple[float, tuple[Any, ...] | None]] = {}

# Dedicated, BOUNDED pool for research-lane DNS so a hung resolver under a wide
# OSINT swarm caps its blast radius here instead of starving asyncio's shared
# default executor (which infra / report tools dispatch onto). getaddrinfo's C
# call can't be interrupted, so bounding the pool — not a per-call timeout — is
# the load-bearing mitigation.
_RESEARCH_EXECUTOR = ThreadPoolExecutor(
    max_workers=8,
    thread_name_prefix="scope-research",
)


def _resolve_host(host: str) -> tuple[Any, ...] | None:
    """Resolve `host` → tuple of ip_address objects, or None on failure.
    Monkeypatch this in tests. NOTE: getaddrinfo has no timeout argument; the
    OS resolver's own timeout bounds it, and the bounded `_RESEARCH_EXECUTOR`
    caps how many can hang at once."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, UnicodeError):
        return None
    addrs: set[Any] = set()
    for info in infos:
        try:
            addrs.add(ipaddress.ip_address(info[4][0]))
        except (ValueError, IndexError):
            continue
    return tuple(addrs) or None


def _resolve_cached(host: str) -> tuple[Any, ...] | None:
    now = time.monotonic()
    hit = _resolve_cache.get(host)
    if hit is not None and now - hit[0] < _RESOLVE_TTL:
        return hit[1]
    res = _resolve_host(host)
    # Coarse cap so an OSINT burst over many distinct hosts can't grow the
    # cache without bound; drop the whole map when it's exceeded (simpler than
    # LRU, and entries are cheap to re-resolve).
    if len(_resolve_cache) >= _RESOLVE_CACHE_MAX:
        _resolve_cache.clear()
    _resolve_cache[host] = (now, res)
    return res


def _ip_is_global(ip: Any) -> bool:
    """True iff `ip` is a globally-routable public address (the research lane's
    allow condition). Denies private/loopback/link-local/reserved/multicast/
    unspecified, CGNAT shared space, and any address bound to a local NIC."""
    if ip in _local_addresses():
        return False
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False
    if ip.version == 4 and ip in _CGNAT_NET:
        return False
    return True


class ScopeStore:
    """Engagement-scoped allow/deny rule store plus the per-call gate.

    One instance per Daemon. Constructed at daemon boot from the engagement
    profile (engagement-origin rules) and from the on-disk scope.db
    (adhoc-origin rules, if any). Adhoc rules persist across daemon
    restarts within the same engagement; engagement rules are reloaded
    from engagement.yaml on every restart.

    All operations are synchronous; the daemon is single-event-loop so
    there's no thread-safety concern. SQLite uses WAL.
    """

    def __init__(
        self,
        db_path: Path | None,
        engagement_id: str,
    ) -> None:
        self.engagement_id = engagement_id
        self.db_path = db_path
        self._rules: list[ScopeRule] = []
        # Research lane policy (default: public / on). Replaced by
        # load_engagement_rules from the profile's scope.research block.
        self._research: ResearchPolicy = ResearchPolicy()
        # SC-1: per-call scope re-check of relayed session commands.
        # Off by default (legacy established-session trust); set from the
        # engagement profile's scope.session_strict by load_engagement_rules.
        self._session_strict: bool = False
        if db_path is not None:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn: sqlite3.Connection | None = sqlite3.connect(
                str(db_path),
                isolation_level=None,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._load_adhoc_from_db()
        else:
            self._conn = None

    # ─── rule loading ────────────────────────────────────────────────────

    def load_engagement_rules(self, profile: dict[str, Any]) -> None:
        """Replace engagement-origin rules from the YAML profile.

        Atomic: removes old engagement rules, inserts the new ones.
        Adhoc rules are not touched.
        """
        scope_block = (profile or {}).get("scope") or {}
        # Research lane policy travels with the engagement scope block.
        self._research = research_config_from_profile(profile)
        # SC-1: opt-in per-call re-check of relayed session commands.
        self._session_strict = bool(
            _coalesce(
                scope_block,
                "session_strict",
                "strict_sessions",
            )
            or False
        )
        in_pats = _coalesce(scope_block, "in_targets", "in") or []
        out_pats = _coalesce(scope_block, "out_targets", "out") or []
        new_rules: list[ScopeRule] = []
        now = time.time()
        for pat in _as_list(in_pats):
            kind, norm = parse_rule(pat)
            new_rules.append(
                ScopeRule(
                    pattern=norm,
                    kind=kind,
                    direction="in",
                    origin="engagement",
                    added_by="engagement.yaml",
                    added_at=now,
                    reason="",
                )
            )
        for pat in _as_list(out_pats):
            kind, norm = parse_rule(pat)
            new_rules.append(
                ScopeRule(
                    pattern=norm,
                    kind=kind,
                    direction="out",
                    origin="engagement",
                    added_by="engagement.yaml",
                    added_at=now,
                    reason="",
                )
            )
        # Swap atomically.
        self._rules = [r for r in self._rules if r.origin != "engagement"] + new_rules
        if self._conn is not None:
            self._conn.execute("DELETE FROM scope_rules WHERE origin='engagement'")
            for r in new_rules:
                self._insert_rule_row(r)

    def _load_adhoc_from_db(self) -> None:
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT pattern,kind,direction,origin,added_by,added_at,"
            "expires_at,one_shot,consumed_at,reason "
            "FROM scope_rules WHERE origin='adhoc'"
        )
        for row in cur.fetchall():
            (
                pat,
                kind,
                direction,
                origin,
                added_by,
                added_at,
                expires_at,
                one_shot,
                consumed_at,
                reason,
            ) = row
            self._rules.append(
                ScopeRule(
                    pattern=pat,
                    kind=kind,
                    direction=direction,
                    origin=origin,
                    added_by=added_by,
                    added_at=added_at,
                    expires_at=expires_at,
                    one_shot=bool(one_shot),
                    consumed_at=consumed_at,
                    reason=reason,
                )
            )

    def _insert_rule_row(self, r: ScopeRule) -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT OR REPLACE INTO scope_rules "
            "(pattern,kind,direction,origin,added_by,added_at,"
            " expires_at,one_shot,consumed_at,reason) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                r.pattern,
                r.kind,
                r.direction,
                r.origin,
                r.added_by,
                r.added_at,
                r.expires_at,
                int(r.one_shot),
                r.consumed_at,
                r.reason,
            ),
        )

    # ─── adhoc rule management ───────────────────────────────────────────

    def add_adhoc(
        self,
        pattern: str,
        direction: Direction = "in",
        ttl_seconds: float | None = None,
        one_shot: bool = False,
        reason: str = "",
        added_by: str = "operator",
        force_kind: str | None = None,
    ) -> ScopeRule:
        if not (reason or "").strip():
            raise ValueError("adhoc rules require a non-empty reason")
        kind, norm = parse_rule(pattern, force_kind=force_kind)
        now = time.time()
        rule = ScopeRule(
            pattern=norm,
            kind=kind,
            direction=direction,
            origin="adhoc",
            added_by=added_by,
            added_at=now,
            expires_at=(now + ttl_seconds) if ttl_seconds else None,
            one_shot=one_shot,
            reason=reason,
        )
        # Replace any prior rule with same key (pattern, direction, origin).
        self._rules = [
            r
            for r in self._rules
            if not (r.pattern == norm and r.direction == direction and r.origin == "adhoc")
        ]
        self._rules.append(rule)
        if self._conn is not None:
            self._insert_rule_row(rule)
        return rule

    def remove(
        self,
        pattern: str,
        direction: Direction = "in",
        force_kind: str | None = None,
    ) -> bool:
        try:
            _, norm = parse_rule(pattern, force_kind=force_kind)
        except ValueError:
            norm = pattern  # let exact-string match fall through
        before = len(self._rules)
        self._rules = [
            r
            for r in self._rules
            if not (r.pattern == norm and r.direction == direction and r.origin == "adhoc")
        ]
        removed = before - len(self._rules)
        if removed and self._conn is not None:
            self._conn.execute(
                "DELETE FROM scope_rules WHERE pattern=? AND direction=? AND origin='adhoc'",
                (norm, direction),
            )
        return bool(removed)

    def rules(self, include_inactive: bool = False) -> list[ScopeRule]:
        now = time.time()
        if include_inactive:
            return list(self._rules)
        return [r for r in self._rules if r.is_active(now)]

    def has_any_in_rule(self) -> bool:
        return any(r.direction == "in" and r.is_active() for r in self._rules)

    def in_scope_origins(self, *, sentinel: str = "https://scope.invalid") -> str:
        """Render the active in-scope rules as a Playwright-style
        `--allowed-origins` value: a ';'-joined list of `scheme://host:*`
        origins. Used to confine a browser-style external MCP server
        (mcp_plugins/browser.yaml + the runner-factory merge step) to the
        engagement at the process level.

        Mapping is lossy — scope is host/IP-based, origins are
        scheme+host+port — so we emit both http+https and any port:
          host_exact  example.internal   -> http://example.internal:*  ; https://example.internal:*
          host_glob   *.example.internal -> http://*.example.internal:* ; https://*.example.internal:*
          network /32 or /128      -> the single host (IPv6 bracketed)
          broader CIDR / wifi      -> skipped (not representable as an origin;
                                      the browser_navigate gate still covers them)

        FAIL-SAFE: if nothing renderable is in scope, returns `sentinel`
        (a non-resolvable origin) so the browser reaches NOTHING until the
        operator sets a host/IP scope — matching the gate's default-deny.
        """
        origins: list[str] = []
        seen: set[str] = set()

        def _add(host: str) -> None:
            for scheme in ("http", "https"):
                o = f"{scheme}://{host}:*"
                if o not in seen:
                    seen.add(o)
                    origins.append(o)

        for r in self.rules(include_inactive=False):
            if r.direction != "in":
                continue
            if r.kind in ("host_exact", "host_glob"):
                _add(r.pattern)
            elif r.kind == "network":
                try:
                    net = ipaddress.ip_network(r.pattern, strict=False)
                except ValueError:
                    continue
                if net.num_addresses == 1:
                    ip = net.network_address
                    _add(f"[{ip}]" if ip.version == 6 else str(ip))
                # broader CIDRs aren't a single browser origin — skip.
            # wifi_* kinds are irrelevant to a browser.
        return ";".join(origins) if origins else sentinel

    # ─── the check ───────────────────────────────────────────────────────

    def check(self, targets: list[Target]) -> CheckResult:
        """Allow IFF every target is in some active 'in' rule AND no
        target is in any active 'out' rule.

        Returns a CheckResult with per-target decisions. The summary
        string is human-readable for the agent's refusal message.
        """
        targets, op_filtered = _split_operator_targets(targets)
        op_note = _operator_filter_note(op_filtered)
        if not targets:
            if op_filtered:
                return CheckResult(
                    allowed=True,
                    decisions=[],
                    summary=f"all targets are operator-side ({op_note}) — scope check skipped",
                )
            return CheckResult(
                allowed=False,
                decisions=[],
                summary="no targets to check (target extraction returned empty)",
            )
        if not self.has_any_in_rule():
            return CheckResult(
                allowed=False,
                decisions=[],
                summary=(
                    "engagement has no scope set. Run: "
                    "`salientctl prefs set scope.in_targets '[…]'` "
                    "or `salientctl scope add <pattern> --reason '…'` "
                    "before any target-bearing tool can run."
                ),
            )
        decisions: list[Decision] = []
        all_allowed = True
        consumed_oneshots: list[ScopeRule] = []
        for t in targets:
            d = self._check_one(t)
            decisions.append(d)
            if d.verdict == "deny":
                all_allowed = False
            elif d.matched_rule is not None and d.matched_rule.one_shot:
                consumed_oneshots.append(d.matched_rule)

        if all_allowed and consumed_oneshots:
            self._consume(consumed_oneshots)

        summary = self._summarize(decisions, allowed=all_allowed)
        if op_filtered:
            summary = f"{summary} (operator-side filtered: {op_note})"
        return CheckResult(allowed=all_allowed, decisions=decisions, summary=summary)

    def dry_check(self, targets: list[Target]) -> CheckResult:
        """Identical verdict to check() but never mutates state — used
        by read-only callers (e.g. `hosts_suggest`) that need to know
        whether a target would be allowed without consuming one-shot
        rules along the way.
        """
        targets, op_filtered = _split_operator_targets(targets)
        op_note = _operator_filter_note(op_filtered)
        if not targets:
            if op_filtered:
                return CheckResult(
                    allowed=True,
                    decisions=[],
                    summary=f"all operator-side ({op_note})",
                )
            return CheckResult(allowed=False, decisions=[], summary="no targets")
        if not self.has_any_in_rule():
            return CheckResult(
                allowed=False,
                decisions=[],
                summary="no in-scope rules",
            )
        decisions = [self._check_one(t) for t in targets]
        all_allowed = all(d.verdict == "allow" for d in decisions)
        summary = self._summarize(decisions, allowed=all_allowed)
        if op_filtered:
            summary = f"{summary} (operator-side filtered: {op_note})"
        return CheckResult(
            allowed=all_allowed,
            decisions=decisions,
            summary=summary,
        )

    def _check_one(self, t: Target) -> Decision:
        now = time.time()
        # 1) Out rules win.
        for r in self._rules:
            if r.direction != "out" or not r.is_active(now):
                continue
            if _rule_matches(r, t):
                return Decision(
                    target=t,
                    verdict="deny",
                    matched_rule=r,
                    reason=f"{t.kind} {t.value} matches out-of-scope rule {r.pattern}",
                )
        # 2) In rules.
        for r in self._rules:
            if r.direction != "in" or not r.is_active(now):
                continue
            if _rule_matches(r, t):
                return Decision(
                    target=t,
                    verdict="allow",
                    matched_rule=r,
                    reason=f"{t.kind} {t.value} matches in-scope rule {r.pattern}",
                )
        # 3) No match → deny.
        return Decision(
            target=t,
            verdict="deny",
            matched_rule=None,
            reason=f"{t.kind} {t.value} is not in any in-scope rule",
        )

    # ─── research lane ─────────────────────────────────────────────────────

    def research_active(self) -> bool:
        """True iff the research lane is enabled (mode != off)."""
        return self._research.mode != "off"

    def session_strict(self) -> bool:
        """True iff the engagement opted into per-call scope re-checking of
        relayed session commands (scope.session_strict). When False
        (default), session_scoped tools keep their legacy established-session
        trust bypass. See SC-1 / docs/SCOPE.md."""
        return self._session_strict

    def research_summary(self) -> dict[str, Any]:
        """Operator-facing snapshot of the research lane policy (for
        `scope list`)."""
        return {
            "mode": self._research.mode,
            "allowlist": [r.pattern for r in self._research.in_rules],
            "internal_tlds": list(self._research.internal_tlds),
        }

    def check_research(
        self,
        targets: list[Target],
        active: bool = False,
    ) -> CheckResult:
        """Verdict for an OSINT/recon (research=True) tool. ADDITIVE to the
        engagement scope: a target is allowed iff it's already in engagement
        scope OR it passes the public floor (globally-routable, not internal,
        not in `out_targets`). Never requires `has_any_in_rule`, so pure-OSINT
        runs work with empty engagement scope. Operator-side targets are NOT
        split out here — the floor denies local-NIC addresses itself.

        `active` (= the tool's `ExtractorSpec.research_active`): when True the
        floor fails CLOSED on a hostname that doesn't resolve (an active probe
        could still reach it via split-horizon DNS). Passive tools fail open."""
        if not targets:
            return CheckResult(
                allowed=False,
                decisions=[],
                summary="no targets to check (extraction returned empty)",
            )
        # Snapshot the rule list once: check_research runs off the event loop
        # (gate() dispatches it onto a dedicated executor so a blocking DNS
        # lookup doesn't stall the daemon), and the loop thread can mutate
        # _rules concurrently (operator scope add). Iterating a snapshot
        # avoids the "list changed size during iteration" race.
        rules = list(self._rules)
        decisions = [self._check_research_one(t, rules, active) for t in targets]
        all_allowed = all(d.verdict == "allow" for d in decisions)
        return CheckResult(
            allowed=all_allowed,
            decisions=decisions,
            summary=self._summarize(decisions, allowed=all_allowed),
        )

    def _check_research_one(
        self,
        t: Target,
        rules: list[ScopeRule],
        active: bool = False,
    ) -> Decision:
        now = time.time()
        # 1) Operator denylist always wins (same as the strict lane).
        for r in rules:
            if r.direction == "out" and r.is_active(now) and _rule_matches(r, t):
                return Decision(
                    target=t,
                    verdict="deny",
                    matched_rule=r,
                    reason=f"{t.kind} {t.value} matches out-of-scope rule {r.pattern}",
                )
        # 2) Already in engagement scope → allow (the operator opted in; this
        #    is what makes the lane purely additive — it never removes a grant).
        for r in rules:
            if r.direction == "in" and r.is_active(now) and _rule_matches(r, t):
                return Decision(
                    target=t,
                    verdict="allow",
                    matched_rule=r,
                    reason=f"{t.kind} {t.value} in engagement scope ({r.pattern})",
                )
        # 3) Research public branch.
        if self._research.mode == "off":
            return Decision(
                target=t,
                verdict="deny",
                matched_rule=None,
                reason=f"{t.kind} {t.value} not in engagement scope (research lane off)",
            )
        if self._research.mode == "allowlist":
            matched = next((r for r in self._research.in_rules if _rule_matches(r, t)), None)
            if matched is None:
                return Decision(
                    target=t,
                    verdict="deny",
                    matched_rule=None,
                    reason=f"{t.kind} {t.value} not in the research allowlist",
                )
        ok, reason = self._research_public_floor(t, active)
        if not ok:
            return Decision(
                target=t,
                verdict="deny",
                matched_rule=None,
                reason=reason,
            )
        return Decision(
            target=t,
            verdict="allow",
            matched_rule=None,
            reason=f"{t.kind} {t.value} allowed via research lane (public)",
        )

    def _research_public_floor(
        self,
        t: Target,
        active: bool = False,
    ) -> tuple[bool, str]:
        """The load-bearing safety floor: a research target may only be a
        genuinely PUBLIC host. Denies private/internal IPs, internal-TLD
        hostnames, and hostnames that resolve to a non-global address.

        On a hostname that does not resolve, `active` decides the posture:
        active resolve-and-touch tools fail CLOSED (can't verify public, and
        split-horizon DNS could still reach it); passive DB-lookup tools fail
        OPEN (they only ever query public databases, never the host)."""
        if t.kind == "ip":
            try:
                ip = ipaddress.ip_address(t.value)
            except ValueError:
                return False, f"unparseable IP {t.value}"
            if not _ip_is_global(ip):
                return False, (
                    f"{t.value} is a private/internal address — the research "
                    f"lane is public-only (add it to engagement scope to reach it)"
                )
            return True, ""
        if t.kind in ("host", "url"):
            host = t.value.lower().rstrip(".")
            for tld in self._research.internal_tlds:
                if host == tld.lstrip(".") or host.endswith(tld):
                    return False, (
                        f"{host} is in an internal namespace ({tld}) — the "
                        f"research lane denies internal hosts"
                    )
            addrs = _resolve_cached(host)
            if addrs is None:
                if active:
                    # Active probe + can't verify public → fail CLOSED. A
                    # split-horizon resolver could still reach an internal host.
                    return False, (
                        f"{host} did not resolve — an active research probe "
                        f"can't verify it's public, so the lane denies it "
                        f"(add it to engagement scope to reach it)"
                    )
                # Passive DB lookup never touches the host → fail open.
                return True, ""
            for a in addrs:
                if not _ip_is_global(a):
                    return False, (
                        f"{host} resolves to non-global {a} — the research "
                        f"lane denies internal/private infrastructure"
                    )
            return True, ""
        return False, (f"{t.kind} {t.value} is not eligible for the research lane")

    def _consume(self, rules: Iterable[ScopeRule]) -> None:
        now = time.time()
        for r in list(rules):
            new = replace(r, consumed_at=now)
            # Swap in-place in self._rules
            for i, existing in enumerate(self._rules):
                if (
                    existing.pattern == r.pattern
                    and existing.direction == r.direction
                    and existing.origin == r.origin
                    and existing.added_at == r.added_at
                ):
                    self._rules[i] = new
                    break
            if self._conn is not None:
                self._conn.execute(
                    "UPDATE scope_rules SET consumed_at=? "
                    "WHERE pattern=? AND direction=? AND origin=? AND added_at=?",
                    (now, r.pattern, r.direction, r.origin, r.added_at),
                )

    def _summarize(self, decisions: list[Decision], allowed: bool) -> str:
        if allowed:
            return "; ".join(d.reason for d in decisions)
        denies = [d for d in decisions if d.verdict == "deny"]
        if not denies:
            return "denied (no decisions)"
        return "; ".join(d.reason for d in denies)

    # ─── decision logging ────────────────────────────────────────────────

    def log_decision(
        self,
        agent: str,
        tool: str,
        args: dict[str, Any],
        targets: list[Target],
        result: CheckResult,
    ) -> None:
        if self._conn is None:
            return
        self._conn.execute(
            "INSERT INTO scope_decisions "
            "(ts,engagement_id,agent,tool,args_json,targets_json,"
            " verdict,matched_rule,reason) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                time.time(),
                self.engagement_id,
                agent,
                tool,
                _json_dumps(args),
                _json_dumps([dataclasses.asdict(t) for t in targets]),
                "allow" if result.allowed else "deny",
                _matched_pattern(result),
                result.summary,
            ),
        )

    def deny_log(
        self,
        since: float | None = None,
        agent: str | None = None,
        tool: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if self._conn is None:
            return []
        clauses = ["verdict='deny'"]
        params: list[Any] = []
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if agent:
            clauses.append("agent = ?")
            params.append(agent)
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        where = " AND ".join(clauses)
        cur = self._conn.execute(
            f"SELECT ts,agent,tool,args_json,targets_json,reason,matched_rule "
            f"FROM scope_decisions WHERE {where} "
            f"ORDER BY ts DESC LIMIT ?",
            (*params, limit),
        )
        out: list[dict[str, Any]] = []
        for row in cur.fetchall():
            ts, agent_, tool_, args_json, targets_json, reason, matched = row
            out.append(
                {
                    "ts": ts,
                    "agent": agent_,
                    "tool": tool_,
                    "args": _json_loads(args_json),
                    "targets": _json_loads(targets_json),
                    "reason": reason,
                    "matched_rule": matched,
                }
            )
        return out

    def counts(self) -> dict[str, int]:
        """Aggregate (allow, deny) counts for sitrep / salient-report."""
        if self._conn is None:
            return {"allow": 0, "deny": 0}
        cur = self._conn.execute(
            "SELECT verdict, COUNT(*) FROM scope_decisions WHERE engagement_id=? GROUP BY verdict",
            (self.engagement_id,),
        )
        out = {"allow": 0, "deny": 0}
        for verdict, n in cur.fetchall():
            out[verdict] = n
        return out

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


# ─── per-turn prompt injection ─────────────────────────────────────────────


def render_scope_block(
    store: ScopeStore | None,
    *,
    max_rules: int = 50,
) -> str:
    """Render the current active scope as a compact block to prepend to
    every agent task message.

    The agents repeatedly asked the operator to confirm scope even after
    it was set — the YAML profile gets stale relative to mid-engagement
    `scope add` operations, and operator answers in the inbox don't
    persist into later turns. This block surfaces the *authoritative*
    store state on every dispatch so the agent can see what is already
    authorized.

    Returns "" when there is nothing to inject (no store wired). Caller
    decides whether to skip rendering or emit a no-scope warning.
    """
    if store is None:
        return ""
    active = list(store.rules(include_inactive=False))
    in_eng = sorted({r.pattern for r in active if r.direction == "in" and r.origin == "engagement"})
    in_adhoc = sorted({r.pattern for r in active if r.direction == "in" and r.origin == "adhoc"})
    out_eng = sorted(
        {r.pattern for r in active if r.direction == "out" and r.origin == "engagement"}
    )
    out_adhoc = sorted({r.pattern for r in active if r.direction == "out" and r.origin == "adhoc"})

    if not (in_eng or in_adhoc or out_eng or out_adhoc):
        return (
            "Active engagement scope: NONE SET.\n"
            "Every target-bearing tool call will be REFUSED until the "
            "operator runs `salientctl prefs set scope.in_targets '[…]'` "
            "or `salientctl scope add …`. Do not re-ask the operator "
            "about scope — they are aware; report findings unrelated to "
            "tool execution and wait for scope to be set."
        )

    def _join(rules: list[str]) -> str:
        if len(rules) <= max_rules:
            return ", ".join(rules)
        head = ", ".join(rules[:max_rules])
        return f"{head}, (+{len(rules) - max_rules} more)"

    lines = [
        "Active engagement scope (authoritative; updated only by `salientctl scope add/remove`):"
    ]
    if in_eng:
        lines.append(f"  Authorized (engagement.yaml): {_join(in_eng)}")
    if in_adhoc:
        lines.append(f"  Authorized (adhoc, current run): {_join(in_adhoc)}")
    if out_eng:
        lines.append(f"  Denied (engagement.yaml): {_join(out_eng)}")
    if out_adhoc:
        lines.append(f"  Denied (adhoc): {_join(out_adhoc)}")
    lines.append("")
    lines.append(
        "The scope gate enforces this list deterministically at every "
        "tool call. Treat it as already-answered: do NOT file "
        '`<ask_operator>` questions of the form "is X in scope?" or '
        '"can I scan Y?" when X/Y is already listed above — proceed. '
        "Do NOT propose `salientctl scope add` to the operator as a "
        "workaround for a REFUSED call; if a target is genuinely "
        "required for the current task and not listed, file ONE "
        "`<ask_operator>` stating the target and why it is needed, "
        "then stop."
    )
    return "\n".join(lines)


# ─── rule-match logic ──────────────────────────────────────────────────────


def _rule_matches(rule: ScopeRule, target: Target) -> bool:
    """Does this rule cover this target?

    Semantics:
      network rule, ip target      → ip ∈ network
      network rule, network target → target ⊆ rule
      network rule, host target    → False (no DNS resolution in v1)

      host_exact rule, host target → equal (after IDNA normalize)
      host_exact rule, ip target   → False

      host_glob rule (`*.suffix`)  → target.host == suffix OR
                                     target.host endswith ".suffix"
      host_glob rule, ip target    → False
    """
    if rule.kind == "network":
        try:
            net = ipaddress.ip_network(rule.pattern, strict=False)
        except ValueError:
            return False
        if target.kind == "ip":
            try:
                return ipaddress.ip_address(target.value) in net
            except ValueError:
                return False
        if target.kind == "network":
            try:
                tn = ipaddress.ip_network(target.value, strict=False)
                # tn/net are both IPv4Network|IPv6Network; subnet_of's stubs
                # require a matching concrete type. A v4/v6 mismatch raises
                # TypeError at runtime, which the caller does not expect here —
                # but ip_network parsing keeps them the same family in practice.
                return tn.subnet_of(net)  # type: ignore[arg-type]
            except ValueError:
                return False
        return False

    if rule.kind == "host_exact":
        if target.kind != "host":
            return False
        return rule.pattern.rstrip(".") == target.value.rstrip(".")

    if rule.kind == "host_glob":
        if target.kind != "host":
            return False
        if not rule.pattern.startswith("*."):
            return False
        suffix = rule.pattern[2:].rstrip(".")
        v = target.value.rstrip(".")
        return v == suffix or v.endswith("." + suffix)

    if rule.kind == "wifi_bssid":
        if target.kind != "wifi_bssid":
            return False
        # Both stored canonical (uppercase + colons), but normalize defensively.
        try:
            return _normalize_bssid(rule.pattern) == _normalize_bssid(target.value)
        except ValueError:
            return False

    if rule.kind == "wifi_ssid":
        if target.kind != "wifi_ssid":
            return False
        return rule.pattern == target.value  # case-sensitive per 802.11

    return False


# ─── the gate (wraps an SdkMcpTool) ────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _ScopeGatedHandler:
    identity: InvocationIdentity
    store: ScopeStore
    dataset: PolicyDataset
    original: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]

    async def __call__(self, args: dict[str, Any]) -> dict[str, Any]:
        invocation = ToolInvocation.normalize(self.identity, args)
        evaluation = await evaluate_scope(invocation, self.store, self.dataset)
        if not evaluation.allowed:
            return _refused(evaluation.reason)
        return await self.original(args)


def gate(
    sdk_tool: Any,  # claude_agent_sdk.SdkMcpTool — duck-typed to avoid hard dep
    wire_name: str,
    agent_name: str,
    store: ScopeStore,
    tool_type: str | None = None,
    *,
    dataset: PolicyDataset | None = None,
) -> Any:
    """Wrap an SdkMcpTool's handler with the scope-enforcement gate.

    Returns a new SdkMcpTool (via dataclasses.replace) with the same
    name/description/schema/annotations and a wrapped handler that:

      1. Looks up the extractor spec by `tool_type.wire_name` (specific)
         falling back to `wire_name` (shared default). If neither is
         present → fail-closed (refused with "unclassified tool").
      2. If local_only → log allow, call original handler.
      3. If none → call original handler (no logging, no check).
      4. Otherwise: extract_targets(spec, args).
         If extraction raises → deny with the parser's reason.
         Else: store.check(targets). Log decision.
         If deny → return REFUSED text. Else: call original handler.

    The (tool_type.wire_name) key disambiguates a wire name shared across
    factories — e.g. several factories may each expose a "scan" tool with
    different field shapes; each gets its own spec via "<type>.scan". Generic
    fallback by wire_name covers the truly-uniform cases ("run" → raw_argv
    everywhere).
    """
    from .registry import get_active

    if isinstance(sdk_tool.handler, _ScopeGatedHandler):
        return sdk_tool

    qualified_name = f"{tool_type}.{wire_name}" if tool_type else wire_name
    identity = InvocationIdentity(
        transport=InvocationTransport.MCP,
        wire_name=wire_name,
        qualified_name=qualified_name,
        agent_id=agent_name,
    )
    active_dataset = dataset or get_active()
    return replace(
        sdk_tool,
        handler=_ScopeGatedHandler(
            identity=identity,
            store=store,
            dataset=active_dataset,
            original=sdk_tool.handler,
        ),
    )


def _refused(reason: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": f"REFUSED (scope): {reason}"}],
        "is_error": True,
    }


# ─── helpers ───────────────────────────────────────────────────────────────


def _as_list(x: Any) -> list[str]:
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    if isinstance(x, list):
        return [str(s) for s in x]
    return [str(x)]


def _coalesce(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None


def _json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, default=str, sort_keys=False)
    except (TypeError, ValueError):
        return json.dumps({"_unrepresentable": repr(obj)})


def _json_loads(s: str) -> Any:
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return s


def _matched_pattern(result: CheckResult) -> str | None:
    for d in result.decisions:
        if d.matched_rule is not None:
            return d.matched_rule.pattern
    return None


# ─── extractor table (which tool fields hold targets) ──────────────────────
#
# Keys are qualified SDK names or MCP/bus compatibility wire names. A tool
# absent from the active dataset fails CLOSED, so the kernel's GENERIC default
# covers only its known SDK schemas, built-in bus tools, and generic networking
# examples. A downstream skin swaps in its domain-specific taxonomy via
# `registry.set_active(PolicyDataset(tool_targets=...))`.
_DEFAULT_TOOL_TARGETS: dict[str, ExtractorSpec] = {
    "builtin.Bash": ExtractorSpec(fields={"command": "raw_argv"}),
    "builtin.Read": ExtractorSpec(local_only=True),
    "builtin.Grep": ExtractorSpec(local_only=True),
    "builtin.Glob": ExtractorSpec(local_only=True),
    "builtin.Write": ExtractorSpec(local_only=True),
    "builtin.Edit": ExtractorSpec(local_only=True),
    "builtin.Agent": ExtractorSpec(none=True),
    "builtin.Task": ExtractorSpec(none=True),
    # Built-in bus tools — never scope-checked (in-process, no remote target).
    # Kept in sync with salient_core.bus._BUS_TOOL_NAMES (minus the domain
    # tools a skin supplies). Listed literally to avoid a policy->bus import.
    "ask_agent": ExtractorSpec(none=True),
    "ask_agents": ExtractorSpec(none=True),
    "ask_consensus": ExtractorSpec(none=True),
    "ask_operator": ExtractorSpec(none=True),
    "ask_partner": ExtractorSpec(none=True),
    "context_count": ExtractorSpec(none=True),
    "context_grep": ExtractorSpec(none=True),
    "context_head": ExtractorSpec(none=True),
    "context_lines": ExtractorSpec(none=True),
    "context_list": ExtractorSpec(none=True),
    "context_read": ExtractorSpec(none=True),
    "context_section": ExtractorSpec(none=True),
    "context_summary": ExtractorSpec(none=True),
    "context_tail": ExtractorSpec(none=True),
    "context_write": ExtractorSpec(none=True),
    "get_skill": ExtractorSpec(none=True),
    "kg_assert": ExtractorSpec(none=True),
    "kg_neighbors": ExtractorSpec(none=True),
    "kg_query": ExtractorSpec(none=True),
    "kg_semantic_query": ExtractorSpec(none=True),
    "kg_stats": ExtractorSpec(none=True),
    "list_agents": ExtractorSpec(none=True),
    "prior_actions": ExtractorSpec(none=True),
    "propose_lesson": ExtractorSpec(none=True),
    "propose_skill": ExtractorSpec(none=True),
    "read_evidence": ExtractorSpec(none=True),
    "record_review": ExtractorSpec(none=True),
    "rule_validate": ExtractorSpec(none=True),
    "search_skills": ExtractorSpec(none=True),
    "spawn_template": ExtractorSpec(none=True),
    "swarm_finish": ExtractorSpec(none=True),
    # Generic networking examples so the gate is exercised standalone.
    "http_get": ExtractorSpec(fields={"url": "url"}),
    "curl": ExtractorSpec(fields={"target": "url_or_host"}),
    "ssh": ExtractorSpec(fields={"host": "host"}),
    "ping": ExtractorSpec(fields={"target": "ip_or_host"}),
    "subnet_probe": ExtractorSpec(fields={"cidrs": "cidr_list"}),
    "run": ExtractorSpec(fields={"command": "raw_argv"}),
    "local_task": ExtractorSpec(local_only=True),
}

# Tools wired into TOOL_TARGETS so far cover the demo path (scanner,
# subdomain, bash, web fetch, generic-scan-by-URL, bus tools).
#
# Adding the rest is mechanical and is tracked in docs/SCOPE.md. Until a
# wire name has an entry here, the gate refuses calls to it with
# "unclassified tool — fail-closed."
#
# This is by design: when you add a new tool to tools.py, the daemon
# will refuse to use it on the first attempt and tell you exactly what
# to do — add a TOOL_TARGETS entry. You can't accidentally ship a new
# tool that's exempt from scope enforcement.


def __getattr__(name: str) -> Any:
    # Tombstone the relocated public constant: the extractor table is now the
    # injectable ``PolicyDataset.tool_targets`` (see policy.registry). Any
    # lingering ``from ...scope import TOOL_TARGETS`` fails loudly here rather
    # than silently binding stale/generic data in the default-deny gate.
    if name == "TOOL_TARGETS":
        raise AttributeError(
            "TOOL_TARGETS was replaced by the injectable policy dataset — "
            "read policy.registry.get_active().tool_targets, or register your "
            "own via policy.registry.set_active(PolicyDataset(...)). The kernel "
            "default lives in policy.defaults.DEFAULT_DATASET."
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
