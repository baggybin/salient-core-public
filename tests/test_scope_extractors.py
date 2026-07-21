"""Characterization tests for the scope-gate target extractor.

`scope.extract_targets` is a security boundary (it decides what a tool is
allowed to talk to) with thin coverage. These tests pin its CURRENT behavior
byte-for-byte BEFORE the extractor-kind registry refactor and the extraction of
domain-specific kinds into a downstream skin, so the mechanical move can be
proven behavior-preserving.

Two groups:
  * GenericExtractorTests    — extractor kinds that STAY in the public kernel.
  * SecuritySkinExtractorTests — kinds that MOVE to the downstream security skin
    (msf_cmd / msf_module / session_command / wifi_*). These assertions travel
    with the kinds to salient-security when they relocate; kept here now so the
    disentangling of msf_cmd from the shared raw_argv branch is guarded.
  * UnknownKindTests         — the registry-miss contract (exact error message)
    that the registry refactor must reproduce for an unregistered kind.
"""

from __future__ import annotations

import unittest

from salient_core.policy import scope as _scope
from salient_core.policy.scope import (
    ExtractorError,
    ExtractorSpec,
    Target,
    extract_targets,
    register_extractor,
    unregister_all_extractors,
)


def _kv(targets):
    return [(t.kind, t.value) for t in targets]


class GenericExtractorTests(unittest.TestCase):
    def test_ip_or_host_ip(self):
        ts = extract_targets(ExtractorSpec(fields={"target": "ip_or_host"}), {"target": "10.0.0.5"})
        self.assertEqual(_kv(ts), [("ip", "10.0.0.5")])

    def test_ip_or_host_host(self):
        ts = extract_targets(
            ExtractorSpec(fields={"target": "ip_or_host"}), {"target": "example.com"}
        )
        self.assertEqual(_kv(ts), [("host", "example.com")])

    def test_ip_or_host_cidr_is_network(self):
        ts = extract_targets(
            ExtractorSpec(fields={"target": "ip_or_host"}), {"target": "10.0.0.0/24"}
        )
        self.assertEqual(_kv(ts), [("network", "10.0.0.0/24")])

    def test_ip_or_host_range_expands(self):
        ts = extract_targets(
            ExtractorSpec(fields={"target": "ip_or_host"}), {"target": "10.0.0.5-10"}
        )
        self.assertEqual(_kv(ts), [("ip", f"10.0.0.{n}") for n in range(5, 11)])

    def test_host_rejects_ip(self):
        with self.assertRaises(ExtractorError):
            extract_targets(ExtractorSpec(fields={"target": "host"}), {"target": "10.0.0.5"})

    def test_url_ok_reduces_to_host(self):
        ts = extract_targets(ExtractorSpec(fields={"u": "url"}), {"u": "https://example.com/x"})
        self.assertEqual(_kv(ts), [("host", "example.com")])

    def test_url_rejects_non_url(self):
        with self.assertRaises(ExtractorError):
            extract_targets(ExtractorSpec(fields={"u": "url"}), {"u": "example.com"})

    def test_url_or_host_accepts_both(self):
        self.assertEqual(
            _kv(extract_targets(ExtractorSpec(fields={"x": "url_or_host"}), {"x": "example.com"})),
            [("host", "example.com")],
        )
        self.assertEqual(
            _kv(
                extract_targets(
                    ExtractorSpec(fields={"x": "url_or_host"}), {"x": "https://a.com/p"}
                )
            ),
            [("host", "a.com")],
        )

    def test_endpoint_host_port(self):
        ts = extract_targets(ExtractorSpec(fields={"x": "endpoint"}), {"x": "10.0.0.5:8080"})
        self.assertEqual(_kv(ts), [("ip", "10.0.0.5")])

    def test_cidr_list(self):
        ts = extract_targets(
            ExtractorSpec(fields={"c": "cidr_list"}), {"c": "10.0.0.0/30, 10.0.1.0/30"}
        )
        self.assertEqual(_kv(ts), [("network", "10.0.0.0/30"), ("network", "10.0.1.0/30")])

    def test_binary_argv_synthesizes_command(self):
        ts = extract_targets(
            ExtractorSpec(fields={"binary": "binary_argv"}),
            {"binary": "curl", "args": ["https://a.com"]},
        )
        self.assertEqual(_kv(ts), [("host", "a.com")])

    def test_raw_argv_extracts_ip(self):
        ts = extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "curl 10.0.0.5"})
        self.assertEqual(_kv(ts), [("ip", "10.0.0.5")])

    def test_raw_argv_multiline(self):
        ts = extract_targets(
            ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "curl https://a.com\nping 10.0.0.9"}
        )
        self.assertEqual(_kv(ts), [("host", "a.com"), ("ip", "10.0.0.9")])

    def test_raw_argv_refuses_obfuscation(self):
        with self.assertRaises(ExtractorError) as cm:
            extract_targets(
                ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "curl $(echo 10.0.0.5)"}
            )
        self.assertIn("refused", str(cm.exception))

    def test_raw_argv_refuses_decimal_encoded_ip(self):
        # 167772165 == inet_aton(10.0.0.5). Without this, a raw_argv command
        # naming an integer-encoded host extracts zero targets -> the scope gate
        # allows the call (empty targets -> allowed) -> out-of-scope reach.
        with self.assertRaises(ExtractorError) as cm:
            extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "nmap 167772165"})
        self.assertIn("integer-encoded IP", str(cm.exception))

    def test_raw_argv_refuses_octal_dotted_ip(self):
        # 012.0.0.5 -> inet_aton reads the leading-zero octet as octal (012 = 10).
        with self.assertRaises(ExtractorError) as cm:
            extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "nmap 012.0.0.5"})
        self.assertIn("octal-encoded IP", str(cm.exception))

    def test_raw_argv_allows_small_ints_and_ports(self):
        # Integers below 2**24 (ports, small counts) are not IP-shaped and must
        # not trip the refusal; a real dotted target alongside still extracts.
        ts = extract_targets(
            ExtractorSpec(fields={"cmd": "raw_argv"}),
            {"cmd": "nmap -p 8080 --top-ports 1000 10.0.0.5"},
        )
        self.assertEqual(_kv(ts), [("ip", "10.0.0.5")])

    def test_raw_argv_no_target_allows(self):
        self.assertEqual(
            extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "ls /tmp"}), []
        )
        # A few more benign, target-less local commands must still pass.
        for cmd in ("jobs -l", "cat ./notes", "python3 -c \"print('a'+'b')\""):
            self.assertEqual(
                extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": cmd}),
                [],
                cmd,
            )

    def test_raw_argv_refuses_unresolved_operator_infra_placeholders(self):
        for command in ("nc <lhost> <lport>", "curl http://<LHOST>:<LPORT>/"):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ExtractorError,
                    "unresolved operator-infrastructure placeholder",
                ):
                    extract_targets(
                        ExtractorSpec(fields={"cmd": "raw_argv"}),
                        {"cmd": command},
                    )

    def test_declared_target_fields_refuse_operator_infra_placeholders(self):
        cases = (
            ("ip_or_host", "<lhost>"),
            ("host", "relay.<RHOST>"),
            ("url", "https://<LHOST>/callback"),
            ("endpoint", "<rhost>:<rport>"),
            ("cidr_list", ["10.0.0.0/24", "<lhost>"]),
        )
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                with self.assertRaisesRegex(
                    ExtractorError,
                    "unresolved operator-infrastructure placeholder",
                ):
                    extract_targets(ExtractorSpec(fields={"target": kind}), {"target": value})

    def test_unlisted_metadata_may_contain_operator_infra_placeholders(self):
        targets = extract_targets(
            ExtractorSpec(fields={"target": "ip_or_host"}),
            {"target": "10.0.0.5", "note": "connect back to <lhost>"},
        )

        self.assertEqual(_kv(targets), [("ip", "10.0.0.5")])

    # ── raw_argv hardening: IPv6 sweep, NFKC, decode→exec, spliced literals ──
    def test_raw_argv_extracts_ipv6(self):
        # IPv6 targets were invisible to the (IPv4-only) sweep before — a raw_argv
        # command naming one extracted nothing → the scope gate never checked it.
        ts = extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "ssh 2001:db8::1"})
        self.assertEqual(_kv(ts), [("ip", "2001:db8::1")])

    def test_raw_argv_extracts_ipv6_zone_id(self):
        # `%zone` is dropped before the scope check (the finding cited zoned IPv6
        # as an evasion — the shape gate rejects the `%`, so it used to slip).
        ts = extract_targets(
            ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "ping6 fe80::1%eth0"}
        )
        self.assertEqual(_kv(ts), [("ip", "fe80::1")])

    def test_raw_argv_ipv6_lookalike_not_a_target(self):
        # A colon-run that isn't a valid IPv6 address (`12:00:00`) must be dropped,
        # not refused — it names no target, so the command is allowed.
        self.assertEqual(
            extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": "sleep 12:00:00"}),
            [],
        )

    def test_raw_argv_nfkc_normalizes_unicode_digits(self):
        # Full-width / homoglyph digits collapse to ASCII before the sweep, so an
        # address can't dodge the IPv4 regex by spelling its digits in Unicode.
        ts = extract_targets(
            ExtractorSpec(fields={"cmd": "raw_argv"}),
            {"cmd": "curl １０.0.0.5"},  # '10.0.0.5' in full-width digits
        )
        self.assertEqual(_kv(ts), [("ip", "10.0.0.5")])

    def test_raw_argv_refuses_decode_into_exec(self):
        # A decode wrapper feeding a dynamic-exec sink hides the target entirely.
        for cmd in (
            "python3 -c \"import base64;exec(base64.b64decode('Zm9v'))\"",
            "echo Zm9v | base64 -d | sh",
            "python3 -c \"import codecs;exec(codecs.decode('sbb','rot13'))\"",
        ):
            with self.assertRaises(ExtractorError) as cm:
                extract_targets(ExtractorSpec(fields={"cmd": "raw_argv"}), {"cmd": cmd})
            self.assertIn("dynamic-exec sink", str(cm.exception), cmd)

    def test_raw_argv_allows_decoder_without_exec_sink(self):
        # A lone decoder that writes to a file (no exec sink) is NOT refused —
        # requiring BOTH wrapper and sink keeps false positives bounded.
        self.assertEqual(
            extract_targets(
                ExtractorSpec(fields={"cmd": "raw_argv"}),
                {"cmd": "base64 -d ./blob > ./out"},
            ),
            [],
        )

    def test_raw_argv_refuses_spliced_address(self):
        # An address reassembled from adjacent quoted fragments dodges the
        # contiguous-token regex; refuse the splice.
        with self.assertRaises(ExtractorError) as cm:
            extract_targets(
                ExtractorSpec(fields={"cmd": "raw_argv"}),
                {"cmd": "ping '1'+'0.'+'0.'+'0.'+'5'"},
            )
        self.assertIn("spliced", str(cm.exception))

    def test_optional_kinds_empty_returns_empty(self):
        self.assertEqual(extract_targets(ExtractorSpec(fields={"x": "ip_optional"}), {"x": ""}), [])
        self.assertEqual(extract_targets(ExtractorSpec(fields={"x": "host_optional"}), {}), [])

    def test_none_spec_returns_empty(self):
        self.assertEqual(extract_targets(ExtractorSpec(none=True), {"x": "<lhost>"}), [])

    def test_local_only_spec_returns_empty(self):
        self.assertEqual(extract_targets(ExtractorSpec(local_only=True), {"x": "<lhost>"}), [])

    def test_at_least_one_raises_when_none_present(self):
        with self.assertRaises(ExtractorError):
            extract_targets(
                ExtractorSpec(fields={"a": "ip_optional", "b": "host_optional"}, at_least_one=True),
                {},
            )

    def test_at_least_one_passes_when_one_present(self):
        ts = extract_targets(
            ExtractorSpec(fields={"a": "ip_optional", "b": "host_optional"}, at_least_one=True),
            {"b": "x.com"},
        )
        self.assertEqual(_kv(ts), [("host", "x.com")])


# NOTE: characterization tests for the offensive extractor kinds
# (msf_cmd / msf_module / session_command / wifi_*) live in the salient-security
# package (tests/test_scope_extractors.py), which owns those kinds. They are
# verified there — before and after the kinds relocate — so the behavior is
# pinned in the package responsible for it.


class UnknownKindTests(unittest.TestCase):
    """The registry-miss contract: an unregistered kind raises ExtractorError
    with this exact message. The extractor-kind registry refactor MUST
    reproduce it for a kind no skin has registered."""

    def test_unknown_kind_raises_exact_message(self):
        with self.assertRaises(ExtractorError) as cm:
            extract_targets(ExtractorSpec(fields={"z": "bogus_kind"}), {"z": "x"})
        self.assertEqual(str(cm.exception), "unknown extractor kind: 'bogus_kind'")


class ExtractorRegistryTests(unittest.TestCase):
    """The seam: a downstream skin registers domain-specific extractor kinds;
    generic kinds are reserved; a registry miss reproduces the historical
    unknown-kind error."""

    def tearDown(self):
        unregister_all_extractors()

    def test_registered_kind_is_dispatched(self):
        def _skin_extractor(ctx):
            return [Target(kind="host", value=str(ctx.raw).upper(), source_field=ctx.field)]

        register_extractor("skin_thing", _skin_extractor)
        ts = extract_targets(ExtractorSpec(fields={"x": "skin_thing"}), {"x": "abc"})
        self.assertEqual(_kv(ts), [("host", "ABC")])

    def test_registered_extractor_can_read_sibling_args(self):
        def _skin_extractor(ctx):
            return [Target(kind="ip", value=ctx.args["sibling"], source_field=ctx.field)]

        register_extractor("skin_sibling", _skin_extractor)
        ts = extract_targets(
            ExtractorSpec(fields={"x": "skin_sibling"}), {"x": "present", "sibling": "10.0.0.9"}
        )
        self.assertEqual(_kv(ts), [("ip", "10.0.0.9")])

    def test_registered_extractor_cannot_emit_placeholder_from_sibling_arg(self):
        def _skin_extractor(ctx):
            return [Target(kind="host", value=ctx.args["sibling"], source_field=ctx.field)]

        register_extractor("skin_sibling", _skin_extractor)

        with self.assertRaisesRegex(
            ExtractorError,
            "unresolved operator-infrastructure placeholder",
        ):
            extract_targets(
                ExtractorSpec(fields={"x": "skin_sibling"}),
                {"x": "present", "sibling": "<rhost>"},
            )

    def test_cannot_register_reserved_core_kind(self):
        with self.assertRaises(ExtractorError) as cm:
            register_extractor("raw_argv", lambda ctx: [])
        self.assertIn("reserved core extractor kind", str(cm.exception))

    def test_duplicate_registration_rejected(self):
        register_extractor("dup", lambda ctx: [])
        with self.assertRaises(ExtractorError):
            register_extractor("dup", lambda ctx: [])

    def test_override_allows_replacement(self):
        register_extractor("ov", lambda ctx: [])
        register_extractor(
            "ov",
            lambda ctx: [Target(kind="host", value="new", source_field=ctx.field)],
            override=True,
        )
        ts = extract_targets(ExtractorSpec(fields={"x": "ov"}), {"x": "y"})
        self.assertEqual(_kv(ts), [("host", "new")])

    def test_reserved_kinds_include_generic_kinds(self):
        # Sanity: every generic kind the kernel handles inline is reserved.
        for k in ("raw_argv", "ip_or_host", "cidr_list", "url", "none"):
            self.assertIn(k, _scope._CORE_KINDS)


class ExtractorSpecImmutabilityTests(unittest.TestCase):
    """Registered policy cannot change through a retained input reference or a
    nested mutation of the spec after construction (kernel-invariant #4)."""

    def test_mutating_the_original_fields_mapping_does_not_affect_extraction(self):
        original = {"target": "ip_or_host"}
        spec = ExtractorSpec(fields=original)

        # Caller mutates the dict it passed in — the spec must be decoupled.
        original["target"] = "none"
        original["injected"] = "raw_argv"

        self.assertEqual(dict(spec.fields), {"target": "ip_or_host"})
        ts = extract_targets(spec, {"target": "10.0.0.5"})
        self.assertEqual(_kv(ts), [("ip", "10.0.0.5")])

    def test_direct_mutation_of_spec_fields_is_rejected(self):
        spec = ExtractorSpec(fields={"target": "ip_or_host"})

        # The registered spec's nested mapping is read-only.
        with self.assertRaises(TypeError):
            spec.fields["target"] = "raw_argv"  # type: ignore[index]
        with self.assertRaises(TypeError):
            spec.fields["injected"] = "none"  # type: ignore[index]

        self.assertEqual(dict(spec.fields), {"target": "ip_or_host"})

    def test_default_empty_fields_is_also_immutable(self):
        spec = ExtractorSpec()
        with self.assertRaises(TypeError):
            spec.fields["x"] = "y"  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
