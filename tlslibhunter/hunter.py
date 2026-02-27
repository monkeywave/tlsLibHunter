"""TLSLibHunter - Core orchestrator for TLS library detection and extraction."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from tlslibhunter.config import HunterConfig
from tlslibhunter.scanner.results import ExtractionResult, ScanResult

if TYPE_CHECKING:
    from tlslibhunter.backends.base import Backend

logger = logging.getLogger("tlslibhunter")


class TLSLibHunter:
    """Main orchestrator for scanning and extracting TLS libraries.

    Supports both simple constructor usage and full configuration via
    HunterConfig dataclass.

    Examples:
        # Simple usage
        hunter = TLSLibHunter("firefox")
        result = hunter.scan()

        # Mobile device
        hunter = TLSLibHunter("com.example.app", mobile=True)

        # Specific device by serial
        hunter = TLSLibHunter("com.example.app", serial="ABC123")

        # Full config
        config = HunterConfig(target="firefox", format="json")
        hunter = TLSLibHunter.from_config(config)

        # Context manager
        with TLSLibHunter("firefox") as hunter:
            result = hunter.scan()
    """

    def __init__(
        self,
        target: str,
        mobile: bool = False,
        serial: str | None = None,
        spawn: bool = False,
        backend: str = "frida",
        timeout: int = 10,
        verbose: bool = False,
    ):
        self._config = HunterConfig(
            target=target,
            mobile=mobile,
            serial=serial,
            spawn=spawn,
            backend=backend,
            timeout=timeout,
            verbose=verbose,
        )
        self._backend: Backend | None = None
        self._device = None
        self._session = None
        self._platform: str | None = None
        self._initialized = False

    @classmethod
    def from_config(cls, config: HunterConfig) -> TLSLibHunter:
        """Create a TLSLibHunter from a HunterConfig dataclass."""
        instance = cls.__new__(cls)
        instance._config = config
        instance._backend = None
        instance._device = None
        instance._session = None
        instance._platform = None
        instance._initialized = False
        return instance

    @staticmethod
    def run(
        target: str,
        extract: bool = True,
        output_dir: str = "./tls_libs",
        **kwargs,
    ) -> tuple[ScanResult, list[ExtractionResult] | None]:
        """One-liner: scan and optionally extract TLS libraries.

        Args:
            target: Process name, PID, or package name.
            extract: Whether to extract libraries after scanning.
            output_dir: Directory for extracted libraries.
            **kwargs: Additional arguments passed to TLSLibHunter constructor.

        Returns:
            Tuple of (ScanResult, list of ExtractionResult or None)
        """
        with TLSLibHunter(target, **kwargs) as hunter:
            result = hunter.scan()
            extractions = None
            if extract and result.libraries:
                extractions = hunter.extract(result, output_dir=output_dir)
            return result, extractions

    def _initialize(self) -> None:
        """Initialize backend, device, and session."""
        if self._initialized:
            return

        from tlslibhunter.backends import get_backend
        from tlslibhunter.utils.process_resolver import resolve_target

        self._backend = get_backend(self._config.backend)

        # Get device
        self._device = self._backend.get_device(
            mobile=self._config.mobile,
            serial=self._config.device_serial,
            host=self._config.host,
            timeout=self._config.timeout,
        )

        # Detect platform
        self._platform = self._backend.get_device_platform(self._device)
        logger.info("Platform: %s", self._platform)

        # Attach or spawn
        target = resolve_target(self._config.target)
        if self._config.spawn:
            self._session = self._backend.spawn(self._device, str(target), timeout=self._config.timeout)
        else:
            self._session = self._backend.attach(self._device, target, timeout=self._config.timeout)

        self._initialized = True

    def scan(self) -> ScanResult:
        """Scan the target process for TLS libraries.

        Returns:
            ScanResult containing detected TLS libraries.
        """
        self._initialize()

        from tlslibhunter.scanner.module_scanner import ModuleScanner

        # Determine package name for Android classification
        package_name = None
        if self._platform == "android" and "." in self._config.target:
            package_name = self._config.target

        scanner = ModuleScanner(
            backend=self._backend,
            session=self._session,
            platform=self._platform,
            package_name=package_name,
            verbose=self._config.verbose,
        )

        try:
            result = scanner.scan(self._config.target)
            result.backend = self._config.backend
            return result
        finally:
            scanner.cleanup()

    def extract(
        self,
        scan_result: ScanResult,
        output_dir: str | None = None,
    ) -> list[ExtractionResult]:
        """Extract detected TLS libraries.

        Args:
            scan_result: Result from scan() containing libraries to extract.
            output_dir: Directory to save extracted libraries.

        Returns:
            List of ExtractionResult for each library.
        """
        self._initialize()

        if output_dir is None:
            output_dir = self._config.effective_output_dir

        from tlslibhunter.extractor.strategy import ExtractionStrategy

        strategy = ExtractionStrategy(
            backend=self._backend,
            session=self._session,
            platform=self._platform,
            output_dir=output_dir,
        )

        results = []
        for lib in scan_result.libraries:
            result = strategy.extract(lib)
            results.append(result)

        return results

    def close(self) -> None:
        """Clean up: detach session."""
        if self._session and self._backend:
            self._backend.detach(self._session)
            self._session = None
        self._initialized = False

    def __enter__(self) -> TLSLibHunter:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
