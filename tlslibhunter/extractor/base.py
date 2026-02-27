"""Abstract base for library extractors."""

from __future__ import annotations

import abc
from typing import Any

from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult


class Extractor(abc.ABC):
    """Abstract base class for library extraction methods."""

    @property
    @abc.abstractmethod
    def method_name(self) -> str:
        """Human-readable name of this extraction method."""

    @abc.abstractmethod
    def can_extract(self, library: DetectedLibrary, platform: str) -> bool:
        """Check if this extractor can handle the given library.

        Args:
            library: The library to extract
            platform: Target platform name

        Returns:
            True if this extractor can attempt extraction
        """

    @abc.abstractmethod
    def extract(
        self,
        library: DetectedLibrary,
        output_path: str,
        backend: Any = None,
        session: Any = None,
    ) -> ExtractionResult:
        """Attempt to extract the library.

        Args:
            library: Library to extract
            output_path: Full path for the extracted file
            backend: Backend instance (for Frida-based extraction)
            session: Session handle (for Frida-based extraction)

        Returns:
            ExtractionResult with success/failure info
        """
