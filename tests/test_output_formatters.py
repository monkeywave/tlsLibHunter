"""Tests for output formatters."""

import json

import pytest

from tlslibhunter.output import get_formatter
from tlslibhunter.scanner.results import DetectedLibrary, ExtractionResult, ScanResult


@pytest.fixture
def sample_result():
    return ScanResult(
        target="firefox",
        platform="linux",
        libraries=[
            DetectedLibrary(
                name="libssl.so.3",
                path="/usr/lib/libssl.so.3",
                size=500000,
                library_type="openssl",
                classification="system",
            ),
            DetectedLibrary(
                name="libnss3.so",
                path="/usr/lib/libnss3.so",
                size=300000,
                library_type="nss",
                classification="system",
            ),
        ],
        total_modules_scanned=150,
        scan_duration_seconds=2.5,
    )


@pytest.fixture
def sample_extractions(sample_result):
    return [
        ExtractionResult(
            library=sample_result.libraries[0],
            success=True,
            output_path="./out/libssl.so.3",
            method="disk_copy",
            size_bytes=500000,
        ),
        ExtractionResult(
            library=sample_result.libraries[1],
            success=False,
            method="disk_copy",
            error="Permission denied",
        ),
    ]


class TestJsonFormatter:
    def test_format_scan(self, sample_result):
        fmt = get_formatter("json")
        output = fmt.format_scan(sample_result)
        data = json.loads(output)
        assert data["target"] == "firefox"
        assert data["tls_library_count"] == 2
        assert len(data["libraries"]) == 2

    def test_format_extractions(self, sample_extractions):
        fmt = get_formatter("json")
        output = fmt.format_extractions(sample_extractions)
        data = json.loads(output)
        assert len(data) == 2
        assert data[0]["success"] is True
        assert data[1]["success"] is False


class TestPlainFormatter:
    def test_format_scan(self, sample_result):
        fmt = get_formatter("plain")
        output = fmt.format_scan(sample_result)
        assert "firefox" in output
        assert "libssl.so.3" in output
        assert "openssl" in output

    def test_format_extractions(self, sample_extractions):
        fmt = get_formatter("plain")
        output = fmt.format_extractions(sample_extractions)
        assert "[OK]" in output
        assert "[FAIL]" in output


class TestTableFormatter:
    def test_format_scan(self, sample_result):
        fmt = get_formatter("table")
        output = fmt.format_scan(sample_result)
        assert "libssl.so.3" in output
        assert "firefox" in output

    def test_format_extractions(self, sample_extractions):
        fmt = get_formatter("table")
        output = fmt.format_extractions(sample_extractions)
        assert "libssl.so.3" in output


class TestGetFormatter:
    def test_valid_formatters(self):
        for name in ("table", "json", "plain"):
            fmt = get_formatter(name)
            assert fmt is not None

    def test_invalid_formatter(self):
        with pytest.raises(ValueError):
            get_formatter("xml")
