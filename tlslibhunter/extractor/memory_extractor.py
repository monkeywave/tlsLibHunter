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
            "done": threading.Event(),
            "failed": False,
            "error": "",
        }

        def on_message(msg, data):
            payload = msg.get("payload") or {}
            if msg.get("type") == "send":
                if payload.get("type") == "chunk":
                    if payload.get("failed"):
                        dump_state["failed"] = True
                        dump_state["error"] = "Memory read failed"
                        dump_state["done"].set()
                        return
                    if dump_state["file"] and data:
                        try:
                            offset = payload.get("offset", 0)
                            dump_state["file"].seek(offset)
                            dump_state["file"].write(data)
                            dump_state["received"] += len(data)
                        except Exception as e:
                            logger.error("Write error: %s", e)
                    if payload.get("final"):
                        dump_state["done"].set()
                elif payload.get("type") == "error":
                    dump_state["error"] = payload.get("message", "Unknown error")
                    logger.warning("Dump error for %s: %s", library.name, dump_state["error"])

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

            with contextlib.suppress(Exception):
                script.unload()

            if dump_state["failed"]:
                # Clean up empty/failed dumps
                if os.path.exists(output_path) and os.path.getsize(output_path) == 0:
                    os.remove(output_path)
                return ExtractionResult(
                    library=library,
                    success=False,
                    method=self.method_name,
                    error=dump_state["error"] or "Memory dump failed",
                )

            size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
            logger.info("Memory dump: %s -> %s (%d bytes)", library.name, output_path, size)
            return ExtractionResult(
                library=library,
                success=True,
                output_path=output_path,
                method=self.method_name,
                size_bytes=size,
            )

        except Exception as e:
            if dump_state.get("file"):
                dump_state["file"].close()
            msg = f"Memory dump failed: {e}"
            logger.error(msg)
            return ExtractionResult(library=library, success=False, method=self.method_name, error=msg)
