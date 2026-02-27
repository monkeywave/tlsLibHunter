"""iOS-specific library extraction via Frida file read."""

from __future__ import annotations

import contextlib
import logging
import os
import threading
from typing import Any

from tlslibhunter.extractor.base import Extractor
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult

logger = logging.getLogger("tlslibhunter.extractor.ios")

_EXTRACTOR_JS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "extractor_agent.js")

CHUNK_SIZE = 64 * 1024
READ_TIMEOUT = 300


class IOSExtractor(Extractor):
    """Extract libraries from iOS using Frida file read."""

    @property
    def method_name(self) -> str:
        return "frida_read"

    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        return platform == "ios" and bool(library.path)

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
                error="Backend/session required",
            )

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        state = {
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
                        state["failed"] = True
                        state["error"] = "File read failed"
                        state["done"].set()
                        return
                    if state["file"] and data:
                        state["file"].write(data)
                        state["received"] += len(data)
                    if payload.get("final"):
                        state["done"].set()
                elif payload.get("type") == "error":
                    state["error"] = payload.get("message", "Unknown")

        try:
            with open(_EXTRACTOR_JS) as f:
                js_source = f.read()

            script = backend.create_script(session, js_source, on_message=on_message)
            exports = getattr(script, "exports_sync", None) or getattr(script, "exports", None)

            state["file"] = open(output_path, "wb")  # noqa: SIM115
            exports.read_file_chunks(library.path, CHUNK_SIZE)
            state["done"].wait(timeout=READ_TIMEOUT)

            if state["file"]:
                state["file"].close()

            with contextlib.suppress(Exception):
                script.unload()

            if state["failed"]:
                if os.path.exists(output_path) and os.path.getsize(output_path) == 0:
                    os.remove(output_path)
                return ExtractionResult(
                    library=library,
                    success=False,
                    method=self.method_name,
                    error=state["error"],
                )

            size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
            logger.info("Frida read: %s -> %s (%d bytes)", library.path, output_path, size)
            return ExtractionResult(
                library=library,
                success=True,
                output_path=output_path,
                method=self.method_name,
                size_bytes=size,
            )
        except Exception as e:
            if state.get("file"):
                state["file"].close()
            return ExtractionResult(
                library=library,
                success=False,
                method=self.method_name,
                error=str(e),
            )
