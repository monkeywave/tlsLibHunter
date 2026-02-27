"""Output formatting modules."""

from tlslibhunter.output.json_formatter import JsonFormatter
from tlslibhunter.output.plain_formatter import PlainFormatter
from tlslibhunter.output.table_formatter import TableFormatter

FORMATTERS = {
    "table": TableFormatter,
    "json": JsonFormatter,
    "plain": PlainFormatter,
}


def get_formatter(name: str = "table"):
    """Get a formatter by name."""
    cls = FORMATTERS.get(name)
    if cls is None:
        raise ValueError(f"Unknown format: {name!r}. Available: {', '.join(FORMATTERS)}")
    return cls()
