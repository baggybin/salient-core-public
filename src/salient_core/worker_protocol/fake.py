"""In-process fake worker for protocol / multiplex / STOP tests.

Simulates a cooperative peer: handles ``call`` tools
``remote.read_file``, ``remote.list_dir``, ``remote.run_command`` (with
optional hang), and respects ``control.terminate_session`` by cancelling
in-flight work.
"""

from __future__ import annotations

import asyncio

from .codec import FrameReader, encode_message
from .session import MultiplexSession
from .types import Message, make_error, make_result


class FakeWorker:
    """Byte-stream peer that speaks the worker protocol."""

    def __init__(
        self,
        session_id: str = "test-session",
        *,
        hang_tools: set[str] | None = None,
        files: dict[str, str] | None = None,
    ) -> None:
        self.session_id = session_id
        self.hang_tools = hang_tools or set()
        self.files = files or {"/allowed/hello.txt": "hello-world\n"}
        self.outbound: list[Message] = []
        self._reader = FrameReader()
        self._session = MultiplexSession(
            session_id=session_id,
            on_outbound=self._capture_outbound,
        )
        self._hang_events: dict[str, asyncio.Event] = {}

    @property
    def terminated(self) -> bool:
        return self._session.terminated

    async def _capture_outbound(self, msg: Message) -> None:
        self.outbound.append(msg)

    async def feed_bytes(self, data: bytes) -> list[Message]:
        """Feed hub→worker bytes; returns newly produced worker→hub messages."""
        before = len(self.outbound)
        for msg in self._reader.feed(data):
            await self._session.handle_inbound(msg, self._handle_call)
        return self.outbound[before:]

    async def feed_message(self, msg: Message) -> list[Message]:
        return await self.feed_bytes(encode_message(msg))

    async def _handle_call(self, msg: Message) -> Message | None:
        tool = str(msg.body.get("tool") or "")
        args = msg.body.get("args") or {}
        if not isinstance(args, dict):
            return make_error(msg.id, "bad_args", "args must be object", session=self.session_id)

        if tool in self.hang_tools:
            ev = asyncio.Event()
            self._hang_events[msg.id] = ev
            self._session.jobs[msg.id] = {"call_id": msg.id, "tool": tool, "state": "running"}
            try:
                await ev.wait()
            except asyncio.CancelledError:
                self._session.jobs.pop(msg.id, None)
                raise
            finally:
                self._hang_events.pop(msg.id, None)

        if tool == "remote.read_file":
            path = str(args.get("path") or "")
            if path not in self.files:
                return make_error(
                    msg.id, "not_found", f"no such file: {path}", session=self.session_id
                )
            return make_result(
                msg.id,
                {"path": path, "content": self.files[path]},
                session=self.session_id,
            )

        if tool == "remote.list_dir":
            path = str(args.get("path") or "")
            prefix = path.rstrip("/") + "/"
            names = sorted(
                {p[len(prefix) :].split("/")[0] for p in self.files if p.startswith(prefix)}
            )
            return make_result(msg.id, {"path": path, "entries": names}, session=self.session_id)

        if tool == "remote.run_command":
            argv = args.get("argv") or []
            if not isinstance(argv, list) or not argv:
                return make_error(msg.id, "bad_args", "argv required", session=self.session_id)
            # Cooperative fake: echo argv, exit 0
            return make_result(
                msg.id,
                {
                    "exit_code": 0,
                    "stdout": " ".join(str(a) for a in argv) + "\n",
                    "stderr": "",
                },
                session=self.session_id,
            )

        return make_error(msg.id, "unknown_tool", f"unknown tool {tool!r}", session=self.session_id)

    def release_hang(self, call_id: str) -> None:
        ev = self._hang_events.get(call_id)
        if ev is not None:
            ev.set()
