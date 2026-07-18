"""Regression pins for the multi-model review fixes on worker_protocol (PR1).

- duplicate in-flight `id` is rejected and does NOT orphan the first task
- terminate() reports HONEST quiescence (ok:false when a call won't stop in time)
- Message.from_dict rejects coerced-falsey bodies and bool versions
"""

from __future__ import annotations

import asyncio
import json
import unittest

from salient_core.worker_protocol import (
    FakeWorker,
    FrameDecodeError,
    MessageType,
    make_call,
    make_control,
    parse_message,
)
from salient_core.worker_protocol.session import MultiplexSession
from salient_core.worker_protocol.types import ControlOp


class DuplicateIdTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_inflight_id_rejected_and_first_survives(self) -> None:
        w = FakeWorker(hang_tools={"remote.run_command"})
        # First call with id "dup" hangs and registers in _inflight.
        await w.feed_message(
            make_call(
                "remote.run_command", {"argv": ["sleep", "9"]}, session=w.session_id, msg_id="dup"
            )
        )
        await asyncio.sleep(0.02)
        self.assertIn("dup", w._session._inflight)
        first_task = w._session._inflight["dup"]

        # Second call reusing "dup" must be rejected, NOT overwrite the slot.
        await w.feed_message(
            make_call(
                "remote.read_file",
                {"path": "/allowed/hello.txt"},
                session=w.session_id,
                msg_id="dup",
            )
        )
        await asyncio.sleep(0.02)
        dup_err = next(
            (m for m in w.outbound if m.id == "dup" and m.type is MessageType.ERROR), None
        )
        self.assertIsNotNone(dup_err)
        assert dup_err is not None
        self.assertEqual(dup_err.body.get("code"), "duplicate_id")
        # The ORIGINAL hung task is still tracked (not orphaned by the duplicate).
        self.assertIs(w._session._inflight.get("dup"), first_task)

        # terminate must reach the original.
        await w.feed_message(
            make_control(ControlOp.TERMINATE_SESSION, session=w.session_id, msg_id="t")
        )
        await asyncio.sleep(0.05)
        self.assertEqual(w._session._inflight, {})


class HonestTerminateAckTests(unittest.IsolatedAsyncioTestCase):
    async def test_uncooperative_call_yields_ok_false(self) -> None:
        outbound: list = []

        async def on_out(m):  # noqa: ANN001
            outbound.append(m)

        sess = MultiplexSession(session_id="s", on_outbound=on_out)
        started = asyncio.Event()

        async def uncooperative(msg):  # noqa: ANN001 — ignores the first cancel
            started.set()
            try:
                await asyncio.sleep(100)
            except asyncio.CancelledError:
                await asyncio.sleep(0.3)  # stalls past the grace window
                raise

        await sess.handle_inbound(make_call("x", {}, session="s", msg_id="c1"), uncooperative)
        await started.wait()
        await sess.terminate(grace=0.05)
        self.assertFalse(sess._terminate_clean, "straggler must make quiescence dishonest")
        await asyncio.sleep(0.35)  # let the drained task settle (no leak warning)

    async def test_cooperative_call_yields_ok_true(self) -> None:
        # The existing FakeWorker hang releases immediately on cancel → clean.
        w = FakeWorker(hang_tools={"remote.run_command"})
        await w.feed_message(
            make_call(
                "remote.run_command", {"argv": ["sleep", "9"]}, session=w.session_id, msg_id="h"
            )
        )
        await asyncio.sleep(0.02)
        await w.feed_message(
            make_control(ControlOp.TERMINATE_SESSION, session=w.session_id, msg_id="t")
        )
        await asyncio.sleep(0.05)
        ack = next(m for m in w.outbound if m.id == "t" and m.type is MessageType.RESULT)
        self.assertTrue(ack.body["result"].get("ok"))
        self.assertTrue(ack.body["result"].get("quiesced"))


class ValidationTests(unittest.TestCase):
    def _raw(self, **over) -> bytes:
        base = {"v": 1, "id": "x", "type": "ping", "body": {}}
        base.update(over)
        return json.dumps(base).encode()

    def test_list_body_rejected(self) -> None:
        with self.assertRaises(FrameDecodeError):
            parse_message(self._raw(body=[]))

    def test_string_body_rejected(self) -> None:
        with self.assertRaises(FrameDecodeError):
            parse_message(self._raw(body=""))

    def test_bool_version_rejected(self) -> None:
        with self.assertRaises(FrameDecodeError):
            parse_message(self._raw(v=True))

    def test_missing_body_defaults_empty(self) -> None:
        msg = parse_message(json.dumps({"v": 1, "id": "x", "type": "ping"}).encode())
        self.assertEqual(msg.body, {})


if __name__ == "__main__":
    unittest.main()
