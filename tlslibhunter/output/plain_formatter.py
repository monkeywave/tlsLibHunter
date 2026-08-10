"""Plain text output formatter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tlslibhunter.output._utils import attached_label
from tlslibhunter.output._utils import human_size as _human_size

if TYPE_CHECKING:
    from tlslibhunter.scanner.results import ExtractionResult, ScanResult


class PlainFormatter:
    """Format scan results as plain text."""

    def format_scan(self, result: ScanResult) -> str:
        lines = []
        lines.append(f"Target: {result.target}")
        # Report the process actually instrumented -- name-based targeting can
        # resolve to one the caller never named.
        attached = attached_label(result)
        if attached is not None:
            lines.append(f"Attached to: {attached}")
            if result.target_mismatch:
                lines.append(f"WARNING: '{result.target}' was requested but NOT the process scanned")
        lines.append(f"Platform: {result.platform}")
        lines.append(f"TLS libraries found: {result.tls_library_count}")
        lines.append("")
        for lib in result.libraries:
            lib_display = f"{lib.library_type} ({lib.detected_version})" if lib.detected_version else lib.library_type
            conf = getattr(lib, "confidence", "high")
            lines.append(
                f"  {lib.name} ({lib_display}, {lib.classification}, conf={conf}) "
                f"- {_human_size(lib.size)} - {lib.path}"
            )
            if lib.matched_patterns:
                lines.append(f"    Patterns: {', '.join(lib.matched_patterns)}")
        lines.append("")
        lines.append(f"Scanned {result.total_modules_scanned} modules in {result.scan_duration_seconds:.2f}s")
        return "\n".join(lines)

    def format_extractions(self, extractions: list[ExtractionResult]) -> str:
        lines = []
        for ext in extractions:
            if ext.success:
                lines.append(
                    f"  [OK] {ext.library.name} -> {ext.output_path} ({ext.method}, {_human_size(ext.size_bytes)})"
                )
            else:
                lines.append(f"  [FAIL] {ext.library.name}: {ext.error}")
        return "\n".join(lines)
