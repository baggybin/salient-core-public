"""Multiplexed in-flight call tracking + control-lane priority helpers.

The hub and tests use this to correlate ``call`` ↔ ``result|error|denied`` by
``id`` and to ensure control messages are not blocked behind hung calls at
the *dispatch* layer (transport must still deliver frames concurrently).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .types import ControlOp, Message, MessageType, make_control, make_error, make_result, new_id

Handler = Callable[[Message], Awaitable[Message | None]]


@dataclass
class MultiplexSession:
    """Tracks in-flight calls for one worker connection.

    ``dispatch`` routes:
    - ``control`` → handled immediately (control lane), may cancel in-flight
    - ``call`` → concurrent task per id
    - ``ping`` → ``pong``
    """

    session_id: str
    on_outbound: Callable[[Message], Awaitable[None]] | None = None
    _inflight: dict[str, asyncio.Task[None]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    terminated: bool = False
    jobs: dict[str, dict[str, Any]] = field(default_factory=dict)
    # True once terminate() has proven every cancelled call finished within the
    # grace window; False if any straggler was abandoned on timeout. Drives an
    # HONEST terminate ack instead of a hardcoded ok:true.
    _terminate_clean: bool = True

    async def handle_inbound(self, msg: Message, call_handler: Handler) -> None:
        if self.terminated and msg.type not in (MessageType.CONTROL, MessageType.PING):
            await self._send(
                make_error(
                    msg.id,
                    "session_terminated",
                    "session already terminated",
                    session=self.session_id,
                )
            )
            return

        if msg.type is MessageType.PING:
            from .types import make_pong

            await self._send(make_pong(msg.id, session=self.session_id))
            return

        if msg.type is MessageType.CONTROL:
            await self._handle_control(msg)
            return

        if msg.type is MessageType.CALL:
            # Terminated-check + duplicate-id reject + task create + register must
            # be ONE atomic critical section. Splitting them lets a terminate()
            # running in between snapshot `_inflight` WITHOUT this task — the call
            # then registers into an already-terminated session and escapes
            # cancellation (the STOP guarantee silently breaks).
            reject: str | None = None
            async with self._lock:
                if self.terminated:
                    reject = "session terminated"
                elif msg.id in self._inflight:
                    # A reused in-flight id would overwrite the first task's slot,
                    # orphaning it from terminate()'s snapshot.
                    reject = "duplicate id"
                else:
                    task = asyncio.create_task(
                        self._run_call(msg, call_handler),
                        name=f"worker-call-{msg.id}",
                    )
                    self._inflight[msg.id] = task

                    def _done(t: asyncio.Task[None], call_id: str = msg.id) -> None:
                        # Identity-aware: only drop the slot if it is still THIS
                        # task, so a late duplicate can't unregister a live one.
                        if self._inflight.get(call_id) is t:
                            self._inflight.pop(call_id, None)

                    task.add_done_callback(_done)
            if reject == "session terminated":
                await self._send(
                    make_error(
                        msg.id, "session_terminated", "session terminated", session=self.session_id
                    )
                )
            elif reject == "duplicate id":
                await self._send(
                    make_error(
                        msg.id,
                        "duplicate_id",
                        f"call id {msg.id!r} already in flight",
                        session=self.session_id,
                    )
                )
            return

        # Unexpected inbound type from peer — ignore or error
        await self._send(
            make_error(
                msg.id, "unexpected_type", f"unexpected type {msg.type}", session=self.session_id
            )
        )

    async def _run_call(self, msg: Message, call_handler: Handler) -> None:
        try:
            reply = await call_handler(msg)
            if reply is not None:
                await self._send(reply)
        except asyncio.CancelledError:
            await self._send(
                make_error(
                    msg.id,
                    "cancelled",
                    "call cancelled (session terminate or interrupt)",
                    session=self.session_id,
                )
            )
            raise
        except Exception as e:  # noqa: BLE001 — surface as wire error
            await self._send(
                make_error(msg.id, "internal", f"{type(e).__name__}: {e}", session=self.session_id)
            )

    async def _handle_control(self, msg: Message) -> None:
        op = str(msg.body.get("op") or "")
        if op == ControlOp.TERMINATE_SESSION or op == ControlOp.SHUTDOWN:
            await self.terminate(reason=op)
            # HONEST ack: `ok`/`quiesced` reflect whether every cancelled call
            # actually finished within the grace window — NOT a hardcoded true.
            # (This layer attests task-level quiescence; the compiled worker must
            # additionally prove OS process-group reaping before claiming ok.)
            await self._send(
                make_result(
                    msg.id,
                    {"ok": self._terminate_clean, "op": op, "quiesced": self._terminate_clean},
                    session=self.session_id,
                )
            )
            return
        if op == ControlOp.LIST_JOBS:
            await self._send(
                make_result(
                    msg.id,
                    {"jobs": list(self.jobs.values())},
                    session=self.session_id,
                )
            )
            return
        await self._send(
            make_error(msg.id, "unknown_op", f"unknown control op {op!r}", session=self.session_id)
        )

    async def terminate(self, *, reason: str = "terminate_session", grace: float = 5.0) -> None:
        self.terminated = True
        async with self._lock:
            tasks = list(self._inflight.values())
            self._inflight.clear()
        for t in tasks:
            t.cancel()
        if tasks:
            # Bound the wait: a handler that swallows CancelledError, blocks in
            # native code, or stalls on a backpressured _send must NOT hang STOP
            # forever. On timeout we abandon the stragglers — the transport close
            # (and, on the real worker, OS-level process-group reaping) is the
            # backstop, and the ack must then report the truth (see _handle_control).
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), timeout=grace
                )
                self._terminate_clean = True
            except TimeoutError:
                self._terminate_clean = False
        self.jobs.clear()

    async def request_terminate(self) -> Message:
        """Build an outbound terminate control message (hub → worker)."""
        return make_control(
            ControlOp.TERMINATE_SESSION,
            session=self.session_id,
            msg_id=new_id(),
        )

    async def _send(self, msg: Message) -> None:
        if self.on_outbound is not None:
            await self.on_outbound(msg)
