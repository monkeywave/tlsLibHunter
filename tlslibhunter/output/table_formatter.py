"""Rich table output formatter."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tlslibhunter.scanner.results import ExtractionResult, ScanResult


def _human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024.0 or unit == "GiB":
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} B"


class TableFormatter:
    """Format scan results as a rich table."""

    def format_scan(self, result: ScanResult) -> str:
        try:
            return self._format_rich(result)
        except ImportError:
            return self._format_plain_fallback(result)

    def _format_rich(self, result: ScanResult) -> str:
        from io import StringIO

        from rich.console import Console
        from rich.table import Table

        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        table = Table(title=f"TLS Libraries in '{result.target}' ({result.platform})")
        table.add_column("#", style="dim", width=4)
        table.add_column("Library", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Class", style="yellow")
        table.add_column("Size", justify="right")
        table.add_column("Path", style="dim")

        for i, lib in enumerate(result.libraries, 1):
            table.add_row(
                str(i),
                lib.name,
                f"{lib.library_type} ({lib.detected_version})" if lib.detected_version else lib.library_type,
                lib.classification,
                _human_size(lib.size),
                lib.path,
            )

        console.print(table)
        summary = f"Scanned {result.total_modules_scanned} modules in {result.scan_duration_seconds:.2f}s"
        console.print(f"\n[dim]{summary}[/dim]")
        return buf.getvalue()

    def _format_plain_fallback(self, result: ScanResult) -> str:
        lines = []
        lines.append(f"TLS Libraries in '{result.target}' ({result.platform})")
        lines.append("=" * 80)
        for i, lib in enumerate(result.libraries, 1):
            lib_display = f"{lib.library_type} ({lib.detected_version})" if lib.detected_version else lib.library_type
            lines.append(
                f"  {i:>3}. {lib.name:<40s} {lib_display:<25s}"
                f" {lib.classification:<8s} {_human_size(lib.size):>10s}  {lib.path}"
            )
        lines.append(f"\nScanned {result.total_modules_scanned} modules in {result.scan_duration_seconds:.2f}s")
        return "\n".join(lines)

    def format_extractions(self, extractions: list[ExtractionResult]) -> str:
        try:
            return self._format_extractions_rich(extractions)
        except ImportError:
            return self._format_extractions_plain(extractions)

    def _format_extractions_rich(self, extractions: list[ExtractionResult]) -> str:
        from io import StringIO

        from rich.console import Console
        from rich.table import Table

        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        table = Table(title="Extraction Results")
        table.add_column("Library", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Method")
        table.add_column("Size", justify="right")
        table.add_column("Output Path", style="dim")

        for ext in extractions:
            status = "[green]OK[/green]" if ext.success else f"[red]FAILED: {ext.error}[/red]"
            table.add_row(
                ext.library.name,
                status,
                ext.method,
                _human_size(ext.size_bytes) if ext.success else "-",
                ext.output_path if ext.success else "",
            )

        console.print(table)
        return buf.getvalue()

    def _format_extractions_plain(self, extractions: list[ExtractionResult]) -> str:
        lines = ["Extraction Results", "=" * 60]
        for ext in extractions:
            status = "OK" if ext.success else f"FAILED: {ext.error}"
            lines.append(f"  {ext.library.name}: {status} ({ext.method}) -> {ext.output_path}")
        return "\n".join(lines)
