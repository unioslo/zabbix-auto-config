from __future__ import annotations

from inline_snapshot import snapshot
from zabbix_auto_config.sourcecollectors import CollectorConfig


def test_collectorconfig() -> None:
    """Test creating a CollectorConfig subclass."""

    class TestConfig(CollectorConfig):
        __collector_name__ = "Test"
        required_str_arg: str
        required_int_arg: int
        optional_arg: str = "default"

    kwargs = {
        "required_str_arg": "test",
        "required_int_arg": 42,
    }

    config = TestConfig.from_kwargs(**kwargs)
    assert config.required_str_arg == "test"
    assert config.required_int_arg == 42

    config = TestConfig.from_kwargs(**kwargs, optional_arg="optional_value")
    assert config.optional_arg == "optional_value"


def test_collectorconfig_name_generated() -> None:
    """Test creating a CollectorConfig subclass with a generated name."""

    class TestConfig(CollectorConfig):
        foo: str = "foo"

    config = TestConfig.from_kwargs()
    assert config.__collector_name__ == snapshot("test_sourcecollectors")
