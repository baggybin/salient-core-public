"""Worker protocol: codec, golden fixtures, multiplex + kill-overtakes-hang."""

from __future__ import annotations

import asyncio
import json
import os
import unittest
from pathlib import Path

from salient_core.worker_protocol import (
    PROTOCOL_VERSION,
    ControlOp,
    FakeWorker,
    FrameDecodeError,
    FrameReader,
    MessageType,
    encode_frame,
    encode_message,
    make_call,
    make_control,
    make_hello,
    make_ping,
    parse_message,
)
from salient_core.worker_protocol.codec import (
    message_from_canonical_json,
    message_to_canonical_json,
)

_GOLDEN_DIR = Path(__file__).parent / "golden" / "worker_protocol"


class CodecTests(unittest.TestCase):
    def test_roundtrip_message(self) -> None:
        msg = make_call(
            "remote.read_file",
            {"path": "/allowed/hello.txt"},
            session="s1",
            msg_id="call-1",
        )
        frame = encode_message(msg)
        reader = FrameReader()
        out = reader.feed(frame)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].type, MessageType.CALL)
        self.assertEqual(out[0].id, "call-1")
        self.assertEqual(out[0].body["tool"], "remote.read_file")
        self.assertEqual(out[0].session, "s1")

    def test_incremental_feed(self) -> None:
        msg = make_ping(session="s", msg_id="p1")
        frame = encode_message(msg)
        reader = FrameReader()
        self.assertEqual(reader.feed(frame[:3]), [])
        self.assertEqual(reader.feed(frame[3:7]), [])
        out = reader.feed(frame[7:])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].type, MessageType.PING)

    def test_oversized_frame_rejected(self) -> None:
        reader = FrameReader(max_payload=16)
        # claim length 100
        import struct

        bad = struct.pack("!I", 100) + b"x" * 20
        with self.assertRaises(FrameDecodeError):
            reader.feed(bad)

    def test_invalid_json(self) -> None:
        frame = encode_frame(b"not-json")
        reader = FrameReader()
        with self.assertRaises(FrameDecodeError):
            reader.feed(frame)

    def test_parse_rejects_bad_type(self) -> None:
        raw = json.dumps({"v": 1, "id": "x", "type": "nope", "body": {}}).encode()
        with self.assertRaises(FrameDecodeError):
            parse_message(raw)


class GoldenTests(unittest.TestCase):
    """Pin canonical message shapes for cross-language (Go) conformance."""

    def test_goldens_exist_and_roundtrip(self) -> None:
        goldens = sorted(_GOLDEN_DIR.glob("*.json"))
        self.assertGreaterEqual(len(goldens), 4, "expected committed golden fixtures")
        for path in goldens:
            text = path.read_text(encoding="utf-8")
            msg = message_from_canonical_json(text)
            # Round-trip through wire codec then back to canonical
            wire = encode_message(msg)
            again = FrameReader().feed(wire)[0]
            self.assertEqual(
                message_to_canonical_json(again),
                text,
                msg=f"golden drift: {path.name}",
            )

    def test_regenerate_guard(self) -> None:
        """If UPDATE_WORKER_PROTOCOL_GOLDENS=1, rewrite fixtures from constructors."""
        if not os.environ.get("UPDATE_WORKER_PROTOCOL_GOLDENS"):
            self.skipTest("set UPDATE_WORKER_PROTOCOL_GOLDENS=1 to regenerate")
        samples = {
            "hello.json": make_hello(
                worker_version="0.1.0",
                os_name="linux",
                arch="amd64",
                hostname="lab-box",
                root="/allowed",
                protocol_version=PROTOCOL_VERSION,
                session=None,
                msg_id="hello-fixed-id",
            ),
            "call_read_file.json": make_call(
                "remote.read_file",
                {"path": "/allowed/hello.txt"},
                session="sess-1",
                msg_id="call-fixed-id",
            ),
            "call_run_command.json": make_call(
                "remote.run_command",
                {"argv": ["uname", "-a"], "shell": False, "timeout_s": 30},
                session="sess-1",
                msg_id="call-run-id",
            ),
            "control_terminate.json": make_control(
                ControlOp.TERMINATE_SESSION,
                session="sess-1",
                msg_id="ctl-term-id",
            ),
            "ping.json": make_ping(session="sess-1", msg_id="ping-id"),
        }
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        for name, msg in samples.items():
            (_GOLDEN_DIR / name).write_text(message_to_canonical_json(msg), encoding="utf-8")


class FakeWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_file(self) -> None:
        w = FakeWorker(files={"/allowed/a.txt": "payload\n"})
        replies = await w.feed_message(
            make_call(
                "remote.read_file", {"path": "/allowed/a.txt"}, session=w.session_id, msg_id="c1"
            )
        )
        # allow task to finish
        await asyncio.sleep(0)
        replies = w.outbound
        self.assertTrue(any(r.type is MessageType.RESULT and r.id == "c1" for r in replies))
        result = next(r for r in replies if r.id == "c1")
        self.assertEqual(result.body["result"]["content"], "payload\n")

    async def test_run_command_echo(self) -> None:
        w = FakeWorker()
        await w.feed_message(
            make_call(
                "remote.run_command",
                {"argv": ["echo", "hi"]},
                session=w.session_id,
                msg_id="c2",
            )
        )
        await asyncio.sleep(0)
        result = next(r for r in w.outbound if r.id == "c2")
        self.assertEqual(result.type, MessageType.RESULT)
        self.assertEqual(result.body["result"]["exit_code"], 0)

    async def test_kill_overtakes_hung_call(self) -> None:
        """Control-lane terminate must cancel an in-flight hung run_command.

        This is the load-bearing STOP wire property for PR1.
        """
        w = FakeWorker(hang_tools={"remote.run_command"})
        # Start a hung call
        await w.feed_message(
            make_call(
                "remote.run_command",
                {"argv": ["sleep", "999"]},
                session=w.session_id,
                msg_id="hung-1",
            )
        )
        # Let the call task start and park on the hang event
        await asyncio.sleep(0.05)
        self.assertIn("hung-1", w._session._inflight)

        # Concurrent second call should still be accepted (multiplex)
        await w.feed_message(
            make_call(
                "remote.read_file",
                {"path": "/allowed/hello.txt"},
                session=w.session_id,
                msg_id="quick-1",
            )
        )
        await asyncio.sleep(0.05)
        quick = next((r for r in w.outbound if r.id == "quick-1"), None)
        self.assertIsNotNone(quick)
        assert quick is not None
        self.assertEqual(quick.type, MessageType.RESULT)

        # Terminate session — must cancel hung call
        await w.feed_message(
            make_control(
                ControlOp.TERMINATE_SESSION,
                session=w.session_id,
                msg_id="term-1",
            )
        )
        await asyncio.sleep(0.1)

        self.assertTrue(w.terminated)
        self.assertEqual(w._session._inflight, {})

        # Hung call gets cancelled error; terminate gets ack result
        hung_err = next(
            (r for r in w.outbound if r.id == "hung-1" and r.type is MessageType.ERROR),
            None,
        )
        self.assertIsNotNone(hung_err, "hung call must surface cancelled error")
        assert hung_err is not None
        self.assertEqual(hung_err.body.get("code"), "cancelled")

        term_ack = next(
            (r for r in w.outbound if r.id == "term-1" and r.type is MessageType.RESULT),
            None,
        )
        self.assertIsNotNone(term_ack, "terminate must be acked")
        assert term_ack is not None
        self.assertTrue(term_ack.body["result"].get("ok"))

    async def test_concurrent_calls(self) -> None:
        w = FakeWorker(
            files={f"/allowed/{i}.txt": f"c{i}\n" for i in range(5)},
        )
        for i in range(5):
            await w.feed_message(
                make_call(
                    "remote.read_file",
                    {"path": f"/allowed/{i}.txt"},
                    session=w.session_id,
                    msg_id=f"c{i}",
                )
            )
        await asyncio.sleep(0.1)
        ids = {r.id for r in w.outbound if r.type is MessageType.RESULT}
        self.assertEqual(ids, {f"c{i}" for i in range(5)})


if __name__ == "__main__":
    unittest.main()
