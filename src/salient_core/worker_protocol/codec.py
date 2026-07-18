"""Length-prefixed frame codec for worker protocol messages.

Wire layout (each frame)::

    uint32 big-endian payload length N
    N bytes UTF-8 JSON object

Max payload size defaults to 16 MiB to bound memory on untrusted peers.
"""

from __future__ import annotations

import json
import struct
from typing import Any

from .types import Message

PROTOCOL_VERSION = 1

_HDR = struct.Struct("!I")
DEFAULT_MAX_PAYLOAD = 16 * 1024 * 1024


class FrameDecodeError(ValueError):
    """Malformed length header or payload."""


def encode_frame(payload: bytes, *, max_payload: int = DEFAULT_MAX_PAYLOAD) -> bytes:
    if len(payload) > max_payload:
        raise ValueError(f"payload {len(payload)} exceeds max {max_payload}")
    return _HDR.pack(len(payload)) + payload


def encode_message(msg: Message, *, max_payload: int = DEFAULT_MAX_PAYLOAD) -> bytes:
    raw = json.dumps(msg.to_dict(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return encode_frame(raw, max_payload=max_payload)


def parse_message(payload: bytes) -> Message:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FrameDecodeError(f"invalid JSON payload: {e}") from e
    if not isinstance(data, dict):
        raise FrameDecodeError("payload must be a JSON object")
    try:
        return Message.from_dict(data)
    except ValueError as e:
        raise FrameDecodeError(str(e)) from e


class FrameReader:
    """Incremental stream decoder: feed bytes, pop complete messages."""

    def __init__(self, *, max_payload: int = DEFAULT_MAX_PAYLOAD) -> None:
        self._buf = bytearray()
        self._max = max_payload

    def feed(self, data: bytes) -> list[Message]:
        self._buf.extend(data)
        out: list[Message] = []
        while True:
            msg = self._try_pop()
            if msg is None:
                break
            out.append(msg)
        return out

    def _try_pop(self) -> Message | None:
        if len(self._buf) < _HDR.size:
            return None
        (n,) = _HDR.unpack_from(self._buf, 0)
        if n > self._max:
            raise FrameDecodeError(f"frame length {n} exceeds max {self._max}")
        total = _HDR.size + n
        if len(self._buf) < total:
            return None
        payload = bytes(self._buf[_HDR.size : total])
        del self._buf[:total]
        return parse_message(payload)

    @property
    def buffered(self) -> int:
        return len(self._buf)


def message_to_canonical_json(msg: Message) -> str:
    """Stable JSON for golden fixtures (sorted keys, indented)."""
    return json.dumps(msg.to_dict(), sort_keys=True, indent=2) + "\n"


def message_from_canonical_json(text: str) -> Message:
    data: Any = json.loads(text)
    if not isinstance(data, dict):
        raise FrameDecodeError("golden must be a JSON object")
    return Message.from_dict(data)
