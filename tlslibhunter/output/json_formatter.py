"""JSON output formatter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tlslibhunter.scanner.results import ExtractionResult, ScanResult


class JsonFormatter:
    """Format scan results as JSON."""

    def format_scan(self, result: ScanResult) -> str:
        return json.dumps(result.to_dict(), indent=2)

    def format_extractions(self, extractions: list[ExtractionResult]) -> str:
        return json.dumps([e.to_dict() for e in extractions], indent=2)
