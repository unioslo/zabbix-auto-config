from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import structlog
import tomli
import zabbix_auto_config.models as models
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from inline_snapshot import snapshot
from pydantic import ValidationError
from zabbix_auto_config.config import get_config
from zabbix_auto_config.config import load_config


def test_sample_config(sample_config: str):
    models.Settings(**tomli.loads(sample_config))


def test_config_extra_field(
    sample_config: str, log_output: structlog.testing.LogCapture
):
    config = tomli.loads(sample_config)
    config["foo"] = "bar"
    models.Settings(**config)
    assert len(log_output.entries) == 1
    assert log_output.entries == snapshot(
        [{"event": "Settings: Got unknown config field 'foo'.", "log_level": "warning"}]
    )


def test_config_extra_field_allowed(
    sample_config: str, log_output: structlog.testing.LogCapture
):
    config = tomli.loads(sample_config)
    config["foo"] = "bar"

    # Allow extra fields for this test
    original_extra = models.Settings.model_config["extra"]  # pyright: ignore[reportTypedDictNotRequiredAccess]
    try:
        models.Settings.model_config["extra"] = "allow"
        models.Settings(**config)
        assert len(log_output.entries) == 0
    finally:
        models.Settings.model_config["extra"] = original_extra


def test_sourcecollectorsettings_defaults():
    # Default setting should be valid
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
    )

    # Default strategy should be to use exponential backoff
    assert settings.failure_strategy == models.FailureStrategy.BACKOFF

    # Snapshot of values
    assert settings.model_dump() == snapshot(
        {
            "module_name": "foo",
            "update_interval": 60,
            "error_tolerance": 0,
            "error_duration": 9999,
            "exit_on_error": False,
            "disable_duration": 0,
            "backoff_factor": 1.5,
            "max_backoff": 3600,
        }
    )


def test_sourcecollectorsettings_no_tolerance() -> None:
    """Setting no error tolerance will cause the error_duration to be set
    to a non-zero value.

    Per note in the docstring of SourceCollectorSettings.error_duration,
    the value of error_duration is set to a non-zero value to ensure that
    the error is not discarded when calling RollingErrorCounter.check().
    """
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_tolerance=0,
        error_duration=0,
    )
    assert settings.error_tolerance == snapshot(0)
    assert settings.error_duration == snapshot(9999)


def test_sourcecollectorsettings_no_error_duration():
    # In order to not have an error_duration, error_tolerance must be 0 too
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_duration=0,
        error_tolerance=0,
    )
    assert settings.error_duration == snapshot(9999)

    # With tolerance we get a default value
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_duration=0,
        error_tolerance=5,
    )

    assert settings.error_duration == snapshot(354)


@given(
    update_interval=st.integers(min_value=0, max_value=100),
    error_tolerance=st.integers(min_value=0, max_value=100),
)
@settings(max_examples=1000)
def test_sourcecollectorsettings_no_error_duration_fuzz(
    update_interval: int, error_tolerance: int
):
    """Test model with a variety of update intervals and error tolerances"""
    # We only check that instantiating the model does not raise an exception
    models.SourceCollectorSettings(
        module_name="foo",
        update_interval=update_interval,
        error_tolerance=error_tolerance,
    )


def test_sourcecollectorsettings_duration_too_short():
    # Error_duration should be greater or equal to the product of
    # error_tolerance and update_interval
    with pytest.raises(ValidationError) as exc_info:
        models.SourceCollectorSettings(
            module_name="foo",
            update_interval=60,
            error_tolerance=5,
            error_duration=180,
        )
    errors = exc_info.value.errors(include_url=False, include_context=False)
    assert len(errors) == snapshot(1)
    assert errors[0] == snapshot(
        {
            "type": "value_error",
            "loc": (),
            "msg": "Value error, Invalid value for error_duration (180). It should be greater than 300: error_tolerance (5) * update_interval (60)",
            "input": {
                "module_name": "foo",
                "update_interval": 60,
                "error_tolerance": 5,
                "error_duration": 180,
            },
        }
    )


def test_sourcecollectorsettings_duration_negative():
    # We should not be able to pass in negative values to error_duration
    with pytest.raises(ValidationError) as exc_info:
        models.SourceCollectorSettings(
            module_name="foo",
            update_interval=60,
            error_tolerance=5,
            error_duration=-1,
        )
    errors = exc_info.value.errors(include_url=False, include_context=False)
    assert len(errors) == 1
    assert errors[0] == snapshot(
        {
            "type": "greater_than_equal",
            "loc": ("error_duration",),
            "msg": "Input should be greater than or equal to 0",
            "input": -1,
        }
    )


def test_load_config_from_path(sample_config_path: Path) -> None:
    """Test that we can load the sample config file from a path."""
    # Load config and dump in JSON mode (only primitive types)
    assert load_config(sample_config_path).model_dump(mode="json") == snapshot(
        {
            "zac": {
                "source_collector_dir": "example/source_collectors/",
                "host_modifier_dir": "example/host_modifiers/",
                "health_file": "/tmp/zac_health.json",
                "failsafe_file": "/tmp/zac_failsafe.json",
                "failsafe_ok_file": "/tmp/zac_failsafe_ok",
                "failsafe_ok_file_strict": True,
                "db": {
                    "user": "zabbix",
                    "password": "secret",
                    "dbname": "zac",
                    "host": "db",
                    "port": 5432,
                    "connect_timeout": 2,
                    "tables": {"hosts": "hosts", "hosts_source": "hosts_source"},
                    "init": {"db": True, "tables": True},
                },
                "logging": {
                    "console": {"enabled": True, "format": "text", "level": "INFO"},
                    "file": {
                        "enabled": True,
                        "format": "json",
                        "level": "INFO",
                        "path": "/path/to/log/file.log",
                        "rotate": True,
                        "max_size_mb": 50,
                        "max_logs": 5,
                    },
                    "level": "INFO",
                    "use_mp_handler": False,
                },
                "process": {
                    "source_merger": {"update_interval": 60},
                    "host_updater": {"update_interval": 60},
                    "hostgroup_updater": {"update_interval": 60},
                    "template_updater": {"update_interval": 60},
                    "garbage_collector": {
                        "update_interval": 86400,
                        "enabled": False,
                        "delete_empty_maintenance": False,
                    },
                },
                "db_uri": "",
            },
            "zabbix": {
                "map_dir": "example/mapping_files/",
                "url": "http://zabbix-web-nginx:8080",
                "username": "Admin",
                "password": "zabbix",
                "dryrun": True,
                "timeout": 60,
                "verify_ssl": True,
                "tags_prefix": "zac_",
                "managed_inventory": ["location"],
                "failsafe": 20,
                "hostgroup_all": "All-hosts",
                "hostgroup_manual": "All-manual-hosts",
                "hostgroup_disabled": "All-auto-disabled-hosts",
                "hostgroup_source_prefix": "Source-",
                "hostgroup_importance_prefix": "Importance-",
                "create_templategroups": True,
                "templategroup_prefix": "Templates-",
                "extra_siteadmin_hostgroup_prefixes": [],
                "prefix_separator": "-",
            },
            "source_collectors": {
                "mysource": {
                    "module_name": "mysource",
                    "update_interval": 60,
                    "error_tolerance": 0,
                    "error_duration": 9999,
                    "exit_on_error": False,
                    "disable_duration": 0,
                    "backoff_factor": 1.5,
                    "max_backoff": 3600.0,
                    "kwarg_passed_to_source": "value",
                    "another_kwarg": "value2",
                },
                "othersource": {
                    "module_name": "mysource",
                    "update_interval": 60,
                    "error_tolerance": 0,
                    "error_duration": 9999,
                    "exit_on_error": False,
                    "disable_duration": 0,
                    "backoff_factor": 2.0,
                    "max_backoff": 3600.0,
                },
                "error_tolerance_source": {
                    "module_name": "mysource",
                    "update_interval": 60,
                    "error_tolerance": 5,
                    "error_duration": 600,
                    "exit_on_error": False,
                    "disable_duration": 3600,
                    "backoff_factor": 1.5,
                    "max_backoff": 3600.0,
                },
                "no_error_handling_source": {
                    "module_name": "mysource",
                    "update_interval": 60,
                    "error_tolerance": 0,
                    "error_duration": 9999,
                    "exit_on_error": False,
                    "disable_duration": -1,
                    "backoff_factor": 1.5,
                    "max_backoff": 3600.0,
                },
            },
        }
    )


def test_get_config_with_path_is_load_config(sample_config_path: Path) -> None:
    """Test that calling `get_config(path)` is equivalent to calling `load_config(path)`."""
    assert load_config(sample_config_path) == get_config(sample_config_path)


def test_get_config_find_config(sample_config_path: Path, tmp_path: Path) -> None:
    """Test that get_config() finds the sample config file."""
    # Copy the sample config file to a temporary location

    # Create a path that exists and is populated with the sample config
    temp_config_path = tmp_path / "exists" / "config.toml"
    temp_config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_config_path.write_text(sample_config_path.read_text())
    assert temp_config_path.exists()

    # Create a path that does not exist
    non_existent_config_path = tmp_path / "nonexistent" / "config.toml"
    non_existent_config_path.parent.mkdir(parents=True, exist_ok=True)
    assert not non_existent_config_path.exists()

    test_paths = [
        # Use non-existent config path first
        non_existent_config_path,
        temp_config_path,
    ]

    # Patch the CONFIG_PATHS to search in test paths
    with patch("zabbix_auto_config.config.CONFIG_PATHS", test_paths):
        # No arg should now search in test paths
        config = get_config()
        sample_config = load_config(sample_config_path)

        # Test that configs are loaded from different paths
        assert config.config_path == temp_config_path
        assert config.config_path != sample_config_path

        # Test that the loaded config matches the sample config
        # (compare in dumped JSON mode to remove excluded fields)
        assert config.model_dump(mode="json") == sample_config.model_dump(mode="json")
