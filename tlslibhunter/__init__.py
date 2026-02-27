"""TLSLibHunter - Identify and extract TLS/SSL libraries from running processes."""

from tlslibhunter.about import __author__, __version__
from tlslibhunter.config import HunterConfig
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult, ScanResult

__all__ = [
    "TLSLibHunter",
    "HunterConfig",
    "ScanResult",
    "DetectedLibrary",
    "ExtractionResult",
    "__author__",
    "__version__",
]


def __getattr__(name):
    # Lazy import TLSLibHunter to avoid importing frida at module level
    if name == "TLSLibHunter":
        from tlslibhunter.hunter import TLSLibHunter

        return TLSLibHunter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
