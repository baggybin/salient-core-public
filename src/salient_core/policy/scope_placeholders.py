"""Fail-closed recognition of unresolved scope-bearing placeholders."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final, assert_never

from .decision import InputValue

_OPERATOR_INFRA: Final = re.compile(r"<(?:[lr]host|[lr]port)>", re.IGNORECASE)


def unresolved_operator_infra_placeholder(value: InputValue) -> str | None:
    """Return the first listener placeholder still present in an invocation value."""
    match value:
        case str():
            regex_match = _OPERATOR_INFRA.search(value)
            return regex_match.group(0) if regex_match is not None else None
        case list() | tuple():
            for item in value:
                if placeholder := unresolved_operator_infra_placeholder(item):
                    return placeholder
            return None
        case Mapping():
            for item in value.values():
                if placeholder := unresolved_operator_infra_placeholder(item):
                    return placeholder
            return None
        case int() | float() | bool() | None:
            return None
        case unreachable:
            assert_never(unreachable)
