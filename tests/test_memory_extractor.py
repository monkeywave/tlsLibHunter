"""Tests for MemoryExtractor's meta/gap/chunk message handling.

We don't run Frida — instead we instrument the backend's create_script call to
capture the on_message handler, then synthesize the message stream a real
agent script would emit. Verifies pre-truncation, gap-zero-fill, partial-success,
and pure-success paths.
"""
from __future__ import annotations

import threading
from unittest.mock import Mock

import pytest

from tlslibhunter.extractor.memory_extractor import MemoryExtractor
from tlslibhunter.scanner.results import DetectedLibrary


@pytest.fixture
def library() -> DetectedLibrary:
    return DetectedLibrary(name="libfoo.so", path="/lib/libfoo.so", size=4096)


def _drive_messages(backend_capture: dict, messages: list[tuple[dict, bytes | None]]):
    """Replay a sequence of (payload, data) tuples via the captured on_message."""
    on_message = backend_capture["on_message"]
    for payload, data in messages:
        on_message({"type": "send", "payload": payload}, data)


def _run_extract(library: DetectedLibrary, tmp_path, messages):
    """Run extractor.extract with a captured backend that replays `messages` on dump_module_chunks call."""
    captured: dict = {}
    output_path = str(tmp_path / "libfoo.so")
    exports = Mock()

    def fake_dump(module_name, chunk_size):
        # Replay the message stream synchronously after exports call.
        threading.Thread(
            target=lambda: _drive_messages(captured, messages),
            daemon=True,
        ).start()
        return True

    exports.dump_module_chunks = fake_dump
    script = Mock()
    script.exports_sync = exports
    script.exports = exports

    def fake_create_script(session, source, on_message=None):
        captured["on_message"] = on_message
        return script

    backend = Mock()
    backend.create_script = fake_create_script

    ext = MemoryExtractor()
    return ext.extract(library, output_path, backend=backend, session=Mock())


def test_extract_full_readable_module(library, tmp_path):
    """All bytes readable, no gaps — clean success."""
    payload_bytes = b"\x41" * 4096
    msgs = [
        ({"type": "meta", "module": "libfoo.so",
          "total_size": 4096, "readable_size": 4096, "gap_count": 0}, None),
        ({"type": "chunk", "module": "libfoo.so", "seq": 0, "offset": 0, "final": False},
         payload_bytes),
        ({"type": "chunk", "module": "libfoo.so", "seq": 1, "offset": 4096, "final": True},
         b""),
    ]
    result = _run_extract(library, tmp_path, msgs)
    assert result.success
    assert result.method == "memory_dump"
    assert result.size_bytes == 4096
    with open(result.output_path, "rb") as f:
        assert f.read() == payload_bytes


def test_extract_partial_with_gap_zero_filled(library, tmp_path):
    """Module has a readable head + a gap + readable tail. Output is module.size,
    gap region is zero-filled, method is memory_dump_partial."""
    head = b"\x41" * 1024
    tail = b"\x42" * 1024
    msgs = [
        # meta: total 4096, readable 2048, 1 gap of 2048 between offsets 1024 and 3072.
        ({"type": "meta", "module": "libfoo.so",
          "total_size": 4096, "readable_size": 2048, "gap_count": 1}, None),
        ({"type": "gap", "module": "libfoo.so", "offset": 1024, "size": 2048}, None),
        ({"type": "chunk", "module": "libfoo.so", "seq": 0, "offset": 0, "final": False},
         head),
        ({"type": "chunk", "module": "libfoo.so", "seq": 1, "offset": 3072, "final": False},
         tail),
        ({"type": "chunk", "module": "libfoo.so", "seq": 2, "offset": 4096, "final": True},
         b""),
    ]
    result = _run_extract(library, tmp_path, msgs)
    assert result.success
    assert result.method == "memory_dump_partial"
    with open(result.output_path, "rb") as f:
        contents = f.read()
    assert len(contents) == 4096
    assert contents[:1024] == head
    assert contents[1024:3072] == b"\x00" * 2048   # gap zero-filled
    assert contents[3072:] == tail


def test_extract_total_failure_when_no_bytes_received(library, tmp_path):
    """If the agent emits an error and never writes data, treat as failure."""
    msgs = [
        ({"type": "meta", "module": "libfoo.so",
          "total_size": 4096, "readable_size": 0, "gap_count": 1}, None),
        ({"type": "gap", "module": "libfoo.so", "offset": 0, "size": 4096}, None),
        ({"type": "error", "module": "libfoo.so",
          "message": "Memory read failed at offset 0"}, None),
        ({"type": "chunk", "module": "libfoo.so", "seq": 0, "offset": 4096, "final": True},
         b""),
    ]
    result = _run_extract(library, tmp_path, msgs)
    assert not result.success
    assert "Memory read failed" in (result.error or "") or "Memory dump failed" in (result.error or "")


def test_extract_legacy_failed_flag(library, tmp_path):
    """Backward compat: the old failed=True chunk shape still aborts cleanly."""
    msgs = [
        ({"type": "chunk", "module": "libfoo.so", "seq": 0, "offset": 0,
          "final": True, "failed": True}, b""),
    ]
    result = _run_extract(library, tmp_path, msgs)
    assert not result.success
