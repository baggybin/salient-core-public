"""Message types and constructors for the remote-worker wire protocol."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class MessageType(StrEnum):
    HELLO = "hello"
    HELLO_ACK = "hello_ack"
    CALL = "call"
    RESULT = "result"
    ERROR = "error"
    DENIED = "denied"
    CONTROL = "control"
    PING = "ping"
    PONG = "pong"


class ControlOp(StrEnum):
    """Abstract control operations — never OS-specific kill signals."""

    TERMINATE_SESSION = "terminate_session"
    LIST_JOBS = "list_jobs"
    SHUTDOWN = "shutdown"


@dataclass(slots=True)
class Message:
    """One protocol message (the JSON body inside a length-prefixed frame)."""

    type: MessageType
    id: str
    v: int = 1
    session: str | None = None
    body: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "v": self.v,
            "id": self.id,
            "type": str(self.type),
            "body": self.body,
        }
        if self.session is not None:
            d["session"] = self.session
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Message:
        if not isinstance(raw, dict):
            raise ValueError("message must be a JSON object")
        try:
            mtype = MessageType(raw["type"])
        except (KeyError, ValueError) as e:
            raise ValueError(f"invalid or missing message type: {raw.get('type')!r}") from e
        mid = raw.get("id")
        if not isinstance(mid, str) or not mid:
            raise ValueError("message id must be a non-empty string")
        v = raw.get("v", 1)
        # bool is a subclass of int — exclude it so `"v": true` can't slip through.
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError("message v must be an int")
        body = raw.get("body")
        if body is None:
            body = {}
        elif not isinstance(body, dict):
            # Do NOT coerce falsey non-dicts ([], "", 0, false) into {} — that
            # silently accepts a malformed body from an untrusted peer.
            raise ValueError("message body must be an object")
        session = raw.get("session")
        if session is not None and not isinstance(session, str):
            raise ValueError("message session must be a string when present")
        return cls(type=mtype, id=mid, v=v, session=session, body=dict(body))


def new_id() -> str:
    return str(uuid.uuid4())


def make_hello(
    *,
    worker_version: str,
    os_name: str,
    arch: str,
    hostname: str,
    root: str,
    protocol_version: int = 1,
    session: str | None = None,
    msg_id: str | None = None,
) -> Message:
    return Message(
        type=MessageType.HELLO,
        id=msg_id or new_id(),
        v=protocol_version,
        session=session,
        body={
            "worker_version": worker_version,
            "os": os_name,
            "arch": arch,
            "hostname": hostname,
            "root": root,
            "protocol_version": protocol_version,
        },
    )


def make_call(
    tool: str,
    args: dict[str, Any],
    *,
    session: str | None = None,
    msg_id: str | None = None,
) -> Message:
    return Message(
        type=MessageType.CALL,
        id=msg_id or new_id(),
        session=session,
        body={"tool": tool, "args": args},
    )


def make_result(
    call_id: str,
    result: dict[str, Any],
    *,
    session: str | None = None,
) -> Message:
    return Message(
        type=MessageType.RESULT,
        id=call_id,
        session=session,
        body={"result": result},
    )


def make_error(
    call_id: str,
    code: str,
    message: str,
    *,
    session: str | None = None,
) -> Message:
    return Message(
        type=MessageType.ERROR,
        id=call_id,
        session=session,
        body={"code": code, "message": message},
    )


def make_control(
    op: ControlOp | str,
    *,
    session: str | None = None,
    msg_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> Message:
    body: dict[str, Any] = {"op": str(op)}
    if extra:
        body.update(extra)
    return Message(
        type=MessageType.CONTROL,
        id=msg_id or new_id(),
        session=session,
        body=body,
    )


def make_ping(*, session: str | None = None, msg_id: str | None = None) -> Message:
    return Message(type=MessageType.PING, id=msg_id or new_id(), session=session, body={})


def make_pong(ping_id: str, *, session: str | None = None) -> Message:
    return Message(type=MessageType.PONG, id=ping_id, session=session, body={})
