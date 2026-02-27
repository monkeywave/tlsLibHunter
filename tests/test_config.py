"""Tests for HunterConfig dataclass."""

import warnings

from tlslibhunter.config import HunterConfig


class TestHunterConfig:
    def test_defaults(self):
        config = HunterConfig(target="firefox")
        assert config.target == "firefox"
        assert config.backend == "frida"
        assert config.timeout == 10
        assert not config.spawn
        assert not config.list_only
        assert config.mobile is False
        assert config.serial is None

    def test_is_mobile_true(self):
        config = HunterConfig(target="app", mobile=True)
        assert config.is_mobile

    def test_is_mobile_serial(self):
        config = HunterConfig(target="app", serial="ABC123")
        assert config.is_mobile
        assert config.device_serial == "ABC123"

    def test_serial_implies_mobile(self):
        config = HunterConfig(target="app", serial="XYZ")
        assert config.is_mobile
        assert config.device_serial == "XYZ"

    def test_is_mobile_false(self):
        config = HunterConfig(target="app")
        assert not config.is_mobile
        assert config.device_serial is None

    def test_mobile_string_deprecation(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            config = HunterConfig(target="app", mobile="ABC123")
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "serial" in str(w[0].message).lower()
            # Should have migrated to serial
            assert config.mobile is True
            assert config.serial == "ABC123"
            assert config.is_mobile
            assert config.device_serial == "ABC123"

    def test_effective_output_dir_default(self):
        config = HunterConfig(target="firefox")
        assert config.effective_output_dir == "./tls_libs_firefox"

    def test_effective_output_dir_custom(self):
        config = HunterConfig(target="firefox", output_dir="/tmp/out")
        assert config.effective_output_dir == "/tmp/out"

    def test_effective_output_dir_sanitizes_slashes(self):
        config = HunterConfig(target="com.example/app")
        assert "/" not in config.effective_output_dir.split("tls_libs_")[-1]
