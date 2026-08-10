"""Memory-based library extraction via Frida."""

from __future__ import annotations

import contextlib
import logging
import os
import threading
from typing import Any

from tlslibhunter.extractor.base import Extractor
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult

logger = logging.getLogger("tlslibhunter.extractor.memory")

_EXTRACTOR_JS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "extractor_agent.js")

CHUNK_SIZE = 64 * 1024  # 64 KiB
DUMP_TIMEOUT = 300  # 5 minutes


class MemoryExtractor(Extractor):
    """Extract libraries by dumping memory via Frida."""

    @property
    def method_name(self) -> str:
        return "memory_dump"

    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        return True  # Universal fallback

    def extract(
        self,
        library: DetectedLibrary,
        output_path: str,
        backend: Any = None,
        session: Any = None,
    ) -> ExtractionResult:
        if not backend or not session:
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error="Backend/session required for memory extraction",
            )

        # Add .memdump suffix if not already present
        if not output_path.endswith(".memdump"):
            output_path = output_path + ".memdump"

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        # State for async chunk handling
        dump_state: dict[str, Any] = {
            "file": None,
            "received": 0,
            "expected_size": None,
            "readable_size": None,
            "gap_count": 0,
            "gap_bytes": 0,
            "done": threading.Event(),
            "failed": False,
            "error": "",
        }

        def on_message(msg, data):
            payload = msg.get("payload") or {}
            if msg.get("type") != "send":
                return
            ptype = payload.get("type")
            if ptype == "meta":
                total = int(payload.get("total_size") or 0)
                dump_state["expected_size"] = total
                dump_state["readable_size"] = int(payload.get("readable_size") or 0)
                dump_state["gap_count"] = int(payload.get("gap_count") or 0)
                # Pre-zero the file to module.size so unwritten gaps are zero-filled
                # and len(output) == module.size for downstream tools (Ghidra/IDA).
                if dump_state["file"] and total > 0:
                    try:
                        dump_state["file"].truncate(total)
                    except Exception as e:
                        logger.error("Truncate error: %s", e)
                return
            if ptype == "gap":
                dump_state["gap_bytes"] += int(payload.get("size") or 0)
                return  # truncate() already zero-filled this region
            if ptype == "chunk":
                if payload.get("failed"):
                    dump_state["failed"] = True
                    dump_state["error"] = "Memory read failed"
                    dump_state["done"].set()
                    return
                if dump_state["file"] and data:
                    try:
                        offset = payload.get("offset", 0)
                        if offset >= 0:
                            dump_state["file"].seek(offset)
                        dump_state["file"].write(data)
                        dump_state["received"] += len(data)
                    except Exception as e:
                        logger.error("Write error: %s", e)
                if payload.get("final"):
                    dump_state["done"].set()
                return
            if ptype == "error":
                dump_state["error"] = payload.get("message", "Unknown error")
                logger.warning("Dump error for %s: %s", library.name, dump_state["error"])

        script = None
        try:
            with open(_EXTRACTOR_JS) as f:
                js_source = f.read()

            script = backend.create_script(session, js_source, on_message=on_message)
            exports = getattr(script, "exports_sync", None) or getattr(script, "exports", None)

            dump_state["file"] = open(output_path, "wb")  # noqa: SIM115
            exports.dump_module_chunks(library.name, CHUNK_SIZE)

            # Wait for completion
            dump_state["done"].wait(timeout=DUMP_TIMEOUT)

            if dump_state["file"]:
                dump_state["file"].close()
                dump_state["file"] = None

            received = dump_state["received"]
            expected = dump_state["expected_size"] or 0
            gap_count = dump_state["gap_count"]
            gap_bytes = dump_state["gap_bytes"]

            if dump_state["failed"] or received == 0:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(output_path)
                return ExtractionResult(
                    library=library,
                    success=False,
                    method=self.method_name,
                    error=dump_state["error"] or "Memory dump failed",
                )

            try:
                size = os.path.getsize(output_path)
            except FileNotFoundError:
                size = 0
            method_name = self.method_name
            if gap_count > 0:
                logger.warning(
                    "Partial memory dump for %s: %d/%d bytes readable, %d gap(s) zero-filled (%d bytes)",
                    library.name,
                    received,
                    expected or size,
                    gap_count,
                    gap_bytes,
                )
                method_name = "memory_dump_partial"
            logger.info("Memory dump: %s -> %s (%d bytes)", library.name, output_path, size)
            return ExtractionResult(
                library=library,
                success=True,
                output_path=output_path,
                method=method_name,
                size_bytes=size,
            )

        except Exception as e:
            if dump_state.get("file"):
                dump_state["file"].close()
            msg = f"Memory dump failed: {e}"
            logger.error(msg)
            return ExtractionResult(library=library, success=False, method=self.method_name, error=msg)
        finally:
            # The unload used to sit inside the try, after the exports call --
            # so the most likely failure (the dump RPC raising) skipped it and
            # left the script resident in the target for the rest of the run.
            backend.unload_script(script)
