"""Wire protocol for reverse-WSS remote tool workers (salient remote agent relay).

Generic, content-free framing shared by the daemon hub (Python) and the
compiled worker (Go). Message bodies are JSON; transport is length-prefixed
frames over a bidirectional byte stream (WSS binary or raw TCP in tests).

STOP is **abstract** (``control.op = terminate_session``) — OS-specific
child reaping (process group / Job Object) is a worker implementation detail,
not part of the frame.

Public surface is re-exported here for ``from salient_core.worker_protocol import …``.
"""

from __future__ import annotations

from .codec import (
    PROTOCOL_VERSION,
    FrameDecodeError,
    FrameReader,
    encode_frame,
    encode_message,
    parse_message,
)
from .fake import FakeWorker
from .session import MultiplexSession
from .types import (
    ControlOp,
    Message,
    MessageType,
    make_call,
    make_control,
    make_error,
    make_hello,
    make_ping,
    make_pong,
    make_result,
    new_id,
)

__all__ = [
    "PROTOCOL_VERSION",
    "ControlOp",
    "FakeWorker",
    "FrameDecodeError",
    "FrameReader",
    "Message",
    "MessageType",
    "MultiplexSession",
    "encode_frame",
    "encode_message",
    "make_call",
    "make_control",
    "make_error",
    "make_hello",
    "make_ping",
    "make_pong",
    "make_result",
    "new_id",
    "parse_message",
]
