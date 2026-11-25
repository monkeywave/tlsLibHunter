"""TLSLibHunter - Core orchestrator for TLS library detection and extraction."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

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
        scan_mode: str = "standard",
    ):
        self._config = HunterConfig(
            target=target,
            mobile=mobile,
            serial=serial,
            spawn=spawn,
            backend=backend,
            timeout=timeout,
            verbose=verbose,
            scan_mode=scan_mode,
        )
        self._backend: Backend | None = None
        self._device = None
        self._session = None
        self._platform: str | None = None
        self._attached: dict | None = None
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
        instance._attached = None
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
            self._session = self._attach_with_timeout_handling(target)

        # Record what was ACTUALLY instrumented. Name-based targeting can land on
        # a process the caller never named, and results must say which one.
        self._attached = self._backend.describe_session(self._device, self._session)
        if self._attached:
            logger.info(
                "Instrumenting '%s' (PID %s)",
                self._attached.get("name") or "?",
                self._attached.get("pid"),
            )
        self._hint_related_android_processes()

        self._initialized = True

    @property
    def attached_pid(self) -> int | None:
        """PID of the process currently instrumented, or None before attach/after close."""
        return (self._attached or {}).get("pid")

    def _hint_related_android_processes(self) -> None:
        """Point the user at sibling/delegate processes that may carry the TLS traffic.

        Purely informational: any failure is logged at debug level and ignored.
        """
        # With --all-processes the related processes are scanned anyway, so the
        # hint ("scan those PIDs") would only be noise.
        if self._platform != "android" or self._config.all_processes:
            return
        try:
            from tlslibhunter.utils import android_related

            serial = self._config.device_serial or getattr(self._device, "id", None)
            target_pid = (self._attached or {}).get("pid")
            target = self._config.target
            package = target if "." in target and not target.isdigit() else None
            related = android_related.find_related_processes(serial, target_pid, package)
            hint = android_related.format_related_hint(related)
            if hint:
                logger.log(*hint)
        except Exception as e:  # never let a hint break the scan
            logger.debug("Related-process lookup skipped: %s", e)

    def _attach_with_timeout_handling(self, target: int | str) -> Any:
        """Attach; on an Android Frida timeout, diagnose it or (with --unfreeze) fix it.

        A process frozen by Android's cached-apps freezer cannot handle the
        ptrace stop Frida waits for, so the attach times out. Unfreezing needs
        root and changes device state, hence it is opt-in.
        """
        from tlslibhunter.backends.base import AttachTimeoutError

        try:
            return self._backend.attach(self._device, target, timeout=self._config.timeout)
        except AttachTimeoutError as e:
            if self._platform != "android" or e.pid is None:
                raise
            return self._recover_android_attach_timeout(e)

    def _recover_android_attach_timeout(self, error: Any) -> Any:
        """Unfreeze and retry once when allowed; otherwise re-raise with a diagnosis."""
        from tlslibhunter.backends.base import AttachTimeoutError
        from tlslibhunter.utils import android_process

        pid = error.pid
        serial = self._config.device_serial or getattr(self._device, "id", None)
        if self._config.unfreeze and android_process.read_freeze_state(pid, serial):
            if android_process.unfreeze(pid, serial):
                logger.warning("Unfroze PID %d (Android cached-apps freezer); Android may re-freeze it.", pid)
                return self._backend.attach(self._device, pid, timeout=self._config.timeout)
            logger.warning("Could not unfreeze PID %d (root required).", pid)

        hint = android_process.diagnose_attach_timeout(pid, serial)
        raise AttachTimeoutError(f"{error}\n{hint}", target=error.target, pid=pid) from error

    def scan(self) -> ScanResult:
        """Scan the target process for TLS libraries.

        Returns:
            ScanResult containing detected TLS libraries.
        """
        self._initialize()

        from tlslibhunter.scanner.module_scanner import ModuleScanner
        from tlslibhunter.utils.process_resolver import resolve_target

        # Determine package name for Android classification
        package_name = None
        if self._platform == "android" and "." in self._config.target:
            package_name = self._config.target

        # Target string used to re-spawn the process for crash recovery (spawn mode only).
        respawn_target = str(resolve_target(self._config.target))

        scanner = ModuleScanner(
            backend=self._backend,
            session=self._session,
            platform=self._platform,
            package_name=package_name,
            verbose=self._config.verbose,
            scan_mode=self._config.scan_mode,
            scan_split_constants=self._config.scan_split_constants,
            scan_stack_strings=self._config.scan_stack_strings,
            scan_rwx_regions=self._config.scan_rwx_regions,
            scan_encoded_strings=self._config.scan_encoded_strings,
            scan_all_modules=self._config.scan_all_modules,
            scan_everything=self._config.scan_everything,
            device=self._device,
            respawn_target=respawn_target,
            spawn_mode=self._config.spawn,
        )

        try:
            result = scanner.scan(self._config.target)
        finally:
            # Adopt whatever session the scanner ended up on. Crash recovery
            # (_reattach) re-spawns the target and replaces it, and extract()
            # short-circuits on _initialized -- so without this, extraction after
            # a recovery would silently run against the dead original session.
            # Runs before cleanup() and on the error path too.
            self._adopt_scanner_session(scanner)
            scanner.cleanup()

        # Labelled after adoption so a recovered scan reports the process the
        # results actually came from.
        result.backend = self._config.backend
        self._label_attached_process(result)
        return result

    def _adopt_scanner_session(self, scanner) -> None:
        """Re-read the scanner's session and refresh the attached-process label."""
        current = getattr(scanner, "session", None)
        if current is self._session:
            return
        self._session = current
        # The recovered session is a different process instance, so the recorded
        # identity no longer applies.
        self._attached = None
        if current is None:
            logger.warning("Target could not be recovered; no session remains for extraction.")
            # Drop out of the initialized state too. Otherwise extract() short-
            # circuits in _initialize() and hands session=None to every
            # extractor, turning one clear failure into N opaque
            # "NoneType has no attribute create_script" errors.
            self._initialized = False
            return
        if self._backend is not None:
            self._attached = self._backend.describe_session(self._device, current)

    def _label_attached_process(self, result: ScanResult) -> None:
        """Stamp the result with the process actually instrumented, and warn on a mismatch.

        Without this the table is titled with the *requested* name, so a scan
        that landed on a different process reads as though it were the intended
        one.
        """
        if not self._attached:
            return
        result.attached_process = self._attached.get("name")
        result.attached_pid = self._attached.get("pid")
        if result.target_mismatch:
            logger.warning(
                "Requested '%s' but instrumented '%s' (PID %s) - the results below describe that process, not '%s'.",
                result.target,
                result.attached_process,
                result.attached_pid,
                result.target,
            )

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
            serial=self._config.serial or getattr(self._device, "id", None),
        )

        # Reorder: extract disk-copyable libraries first (instant), then
        # DSC/memory libraries (the first DSC extraction triggers full cache
        # build; subsequent ones are cache hits).
        libs = scan_result.libraries
        disk_libs = [lib for lib in libs if lib.path and os.path.isfile(lib.path)]
        other_libs = [lib for lib in libs if not lib.path or not os.path.isfile(lib.path)]
        ordered_libs = disk_libs + other_libs

        results = []
        total = len(ordered_libs)
        for i, lib in enumerate(ordered_libs, 1):
            logger.info("Extracting [%d/%d] %s...", i, total, lib.name)
            result = strategy.extract(lib)
            results.append(result)

        return results

    def close(self) -> None:
        """Detach the session and release the backend and device.

        Idempotent, and re-openable: _initialize() rebuilds the backend and
        device from scratch, so `with TLSLibHunter(...)` twice in one process
        still works. Nothing process-global is torn down here for exactly that
        reason.
        """
        if self._session is not None and self._backend is not None:
            self._backend.detach(self._session)
        self._session = None
        if self._backend is not None:
            self._backend.close()
        self._backend = None
        self._device = None
        self._attached = None
        self._initialized = False

    def __enter__(self) -> TLSLibHunter:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
