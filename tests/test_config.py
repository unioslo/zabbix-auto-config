from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import Optional
from unittest.mock import patch

import pytest
import structlog
import tomli
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from inline_snapshot import snapshot
from pydantic import ValidationError
from zabbix_auto_config.config import DBSettings
from zabbix_auto_config.config import DBTableSettings
from zabbix_auto_config.config import FailureStrategy
from zabbix_auto_config.config import GarbageCollectorSettings
from zabbix_auto_config.config import LoggingSettings
from zabbix_auto_config.config import LogLevel
from zabbix_auto_config.config import MaintenanceGcSettings
from zabbix_auto_config.config import ProcessesSettings
from zabbix_auto_config.config import Settings
from zabbix_auto_config.config import SourceCollectorSettings
from zabbix_auto_config.config import ZabbixSettings
from zabbix_auto_config.config import ZacSettings
from zabbix_auto_config.config import get_config
from zabbix_auto_config.config import load_config


def test_sample_config(sample_config: str):
    Settings(**tomli.loads(sample_config))


def test_config_extra_field(
    sample_config: str, log_output: structlog.testing.LogCapture
):
    config = tomli.loads(sample_config)
    config["foo"] = "bar"
    Settings(**config)
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
    original_extra = Settings.model_config["extra"]  # pyright: ignore[reportTypedDictNotRequiredAccess]
    try:
        Settings.model_config["extra"] = "allow"
        Settings(**config)
        assert len(log_output.entries) == 0
    finally:
        Settings.model_config["extra"] = original_extra


def test_sourcecollectorsettings_defaults():
    # Default setting should be valid
    settings = SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
    )

    # Default strategy should be to use exponential backoff
    assert settings.failure_strategy == FailureStrategy.BACKOFF

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
    settings = SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_tolerance=0,
        error_duration=0,
    )
    assert settings.error_tolerance == snapshot(0)
    assert settings.error_duration == snapshot(9999)


def test_sourcecollectorsettings_no_error_duration():
    # In order to not have an error_duration, error_tolerance must be 0 too
    settings = SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_duration=0,
        error_tolerance=0,
    )
    assert settings.error_duration == snapshot(9999)

    # With tolerance we get a default value
    settings = SourceCollectorSettings(
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
    SourceCollectorSettings(
        module_name="foo",
        update_interval=update_interval,
        error_tolerance=error_tolerance,
    )


def test_sourcecollectorsettings_duration_too_short():
    # Error_duration should be greater or equal to the product of
    # error_tolerance and update_interval
    with pytest.raises(ValidationError) as exc_info:
        SourceCollectorSettings(
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
        SourceCollectorSettings(
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
                    "tables": {
                        "hosts": "hosts",
                        "hosts_source": "hosts_source",
                        "hosts_pending_deletion": "hosts_pending_deletion",
                    },
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
                        "hosts": {"enabled": True, "retention_days": 90},
                        "maintenances": {"enabled": True, "delete_empty": False},
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


@pytest.mark.parametrize(
    "inp,expect",
    [
        # Lower case values
        ["notset", LogLevel.NOTSET],
        ["debug", LogLevel.DEBUG],
        ["info", LogLevel.INFO],
        ["warn", LogLevel.WARNING],  # alias for warning
        ["warning", LogLevel.WARNING],
        ["error", LogLevel.ERROR],
        ["fatal", LogLevel.CRITICAL],  # alias for critical
        ["critical", LogLevel.CRITICAL],
        # Upper case values
        ["NOTSET", LogLevel.NOTSET],
        ["DEBUG", LogLevel.DEBUG],
        ["INFO", LogLevel.INFO],
        ["WARN", LogLevel.WARNING],  # alias for warning
        ["WARNING", LogLevel.WARNING],
        ["ERROR", LogLevel.ERROR],
        ["FATAL", LogLevel.CRITICAL],  # alias for critical
        ["CRITICAL", LogLevel.CRITICAL],
        # Numeric values
        [0, LogLevel.NOTSET],
        [10, LogLevel.DEBUG],
        [20, LogLevel.INFO],
        [30, LogLevel.WARNING],
        [40, LogLevel.ERROR],
        [50, LogLevel.CRITICAL],
        # Numeric values as strings
        ["0", LogLevel.NOTSET],
        ["10", LogLevel.DEBUG],
        ["20", LogLevel.INFO],
        ["30", LogLevel.WARNING],
        ["40", LogLevel.ERROR],
        ["50", LogLevel.CRITICAL],
        # Invalid values (uses default level)
        ["invalid", LogLevel.ERROR],
        [None, LogLevel.ERROR],
    ],
)
def test_log_level(inp: Any, expect: LogLevel) -> None:
    assert LogLevel(inp) == expect


def test_logging_settings_log_level_serialize() -> None:
    conf = LoggingSettings()
    conf.file.path = Path("/path/to/logfile.log")  # bogus path

    # Serialize to dict (in JSON mode):
    conf_dict = conf.model_dump(mode="json")
    assert conf_dict["level"] == "INFO"
    assert conf_dict["console"]["level"] == "INFO"
    assert conf_dict["file"]["level"] == "INFO"

    # Serialize to JSON:
    conf_json = conf.model_dump_json(indent=2)
    assert conf_json == snapshot(
        """\
{
  "console": {
    "enabled": true,
    "format": "text",
    "level": "INFO"
  },
  "file": {
    "enabled": true,
    "format": "json",
    "level": "INFO",
    "path": "/path/to/logfile.log",
    "rotate": true,
    "max_size_mb": 50,
    "max_logs": 5
  },
  "level": "INFO",
  "use_mp_handler": false
}\
"""
    )


@pytest.mark.parametrize(
    "timeout,expect",
    [
        (1, 1),
        (60, 60),
        (1234, 1234),
        (0, None),
        pytest.param(
            -1,
            None,
            marks=pytest.mark.xfail(
                reason="Timeout must be 0 or greater.",
                strict=True,
                raises=ValidationError,
            ),
            id="-1",
        ),
    ],
)
def test_zabbix_settings_timeout(timeout: int, expect: Optional[int]) -> None:
    settings = ZabbixSettings(
        map_dir="",
        url="",
        username="",
        password="",
        dryrun=False,
        timeout=timeout,
    )
    assert settings.timeout == expect


def test_failure_strategy_supports_error_tolerance() -> None:
    """Test that only EXIT and DISABLE support error tolerance."""
    for strategy in FailureStrategy:
        if strategy in (FailureStrategy.EXIT, FailureStrategy.DISABLE):
            assert strategy.supports_error_tolerance()
        else:
            assert not strategy.supports_error_tolerance()


def _get_zac_settings(config: Settings, db_uri: str) -> ZacSettings:
    return ZacSettings(
        source_collector_dir=config.zac.source_collector_dir,
        host_modifier_dir=config.zac.host_modifier_dir,
        db_uri=db_uri,
        # Omit DBSettings
    )


def test_zacsettings_db_uri_all(config: Settings):
    """Parse a PostgreSQL connection string with all args."""
    settings = _get_zac_settings(
        config,
        "dbname='zac' user='zabbix' host='localhost' password='secret' port=5432 connect_timeout=2",
    )

    assert settings.db.model_dump(mode="json") == snapshot(
        {
            "user": "zabbix",
            "password": "secret",
            "dbname": "zac",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 2,
            "tables": {
                "hosts": "hosts",
                "hosts_source": "hosts_source",
                "hosts_pending_deletion": "hosts_pending_deletion",
            },
            "init": {"db": True, "tables": True},
        }
    )

    assert settings.db.get_connect_kwargs() == snapshot(
        {
            "dbname": "zac",
            "user": "zabbix",
            "password": "secret",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 2,
        }
    )


def test_zacsettings_db_uri_only_required(config: Settings):
    """Parse a PostgreSQL connection string with only required args."""
    settings = _get_zac_settings(
        config,
        "user='zabbix' password='secret'",
    )

    assert settings.db.model_dump(mode="json") == snapshot(
        {
            "user": "zabbix",
            "password": "secret",
            "dbname": "zac",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 5,
            "tables": {
                "hosts": "hosts",
                "hosts_source": "hosts_source",
                "hosts_pending_deletion": "hosts_pending_deletion",
            },
            "init": {"db": True, "tables": True},
        }
    )

    assert settings.db.get_connect_kwargs() == snapshot(
        {
            "dbname": "zac",
            "user": "zabbix",
            "password": "secret",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 5,
        }
    )


def test_zacsettings_db_uri_extra(config: Settings):
    """Parse a PostgreSQL connection string with all args + extra args."""
    settings = _get_zac_settings(
        config,
        "dbname='zac' user='zabbix' host='localhost' password='secret' port=5432 connect_timeout=2",
    )

    assert settings.db.model_dump(mode="json") == snapshot(
        {
            "user": "zabbix",
            "password": "secret",
            "dbname": "zac",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 2,
            "tables": {
                "hosts": "hosts",
                "hosts_source": "hosts_source",
                "hosts_pending_deletion": "hosts_pending_deletion",
            },
            "init": {"db": True, "tables": True},
        }
    )

    assert settings.db.get_connect_kwargs() == snapshot(
        {
            "dbname": "zac",
            "user": "zabbix",
            "password": "secret",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 2,
        }
    )


def test_zacsettings_db_uri_empty_values_and_extras(config: Settings):
    """Parse a PostgreSQL connection string with some empty values and extra kwargs."""
    settings = _get_zac_settings(
        config,
        "user='zabbix' password='' sslmode='require' passfile='/path/to/passfile'",
    )

    assert settings.db.model_dump(mode="json") == snapshot(
        {
            "user": "zabbix",
            "password": "",
            "dbname": "zac",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 5,
            "tables": {
                "hosts": "hosts",
                "hosts_source": "hosts_source",
                "hosts_pending_deletion": "hosts_pending_deletion",
            },
            "init": {"db": True, "tables": True},
            "sslmode": "require",
            "passfile": "/path/to/passfile",
        }
    )

    assert settings.db.get_connect_kwargs() == snapshot(
        {
            "dbname": "zac",
            "user": "zabbix",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 5,
            "sslmode": "require",
            "passfile": "/path/to/passfile",
        }
    )


def test_zacsettings_db_uri_missing_all(config: Settings):
    """Parse a PostgreSQL connection string with no args."""
    settings = _get_zac_settings(
        config,
        "",
    )

    assert settings.db.model_dump(mode="json") == snapshot(
        {
            "user": "",
            "password": "",
            "dbname": "zac",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 2,
            "tables": {
                "hosts": "hosts",
                "hosts_source": "hosts_source",
                "hosts_pending_deletion": "hosts_pending_deletion",
            },
            "init": {"db": True, "tables": True},
        }
    )

    assert settings.db.get_connect_kwargs() == snapshot(
        {"dbname": "zac", "host": "localhost", "port": 5432, "connect_timeout": 2}
    )


def test_zacsettings_dbsettings(config: Settings) -> None:
    """Test ZacSettings with DBSettings."""
    config.zac.db = DBSettings(
        user="zac",
        password="secret",
        dbname="zac",
        host="localhost",
        port=5432,
        connect_timeout=2,
        # Extra kwargs
        sslmode="require",
        passfile="/path/to/passfile",
    )

    assert config.zac.db.get_connect_kwargs() == snapshot(
        {
            "dbname": "zac",
            "user": "zac",
            "password": "secret",
            "host": "localhost",
            "port": 5432,
            "connect_timeout": 2,
            "sslmode": "require",
            "passfile": "/path/to/passfile",
        }
    )


def test_dbsettings_extra_kwargs() -> None:
    """Test DBSettings with extra kwargs."""
    db = DBSettings(
        user="zac",
        password="secret",
        dbname="zac",
        host="localhost",
        port=5432,
        connect_timeout=2,
        # Extra kwargs (included)
        sslmode="require",
        passfile="/path/to/passfile",
        # Extra kwargs (ignored)
        dict_kwarg={"extra": "value"},
        list_kwarg=["extra", "value"],
        tuple_kwarg=("extra", "value"),
        set_kwarg={"extra", "value"},
        none_kwarg=None,
    )

    assert db.extra_kwargs() == snapshot(
        {"sslmode": "require", "passfile": "/path/to/passfile"}
    )


def test_dbtablesettings_duplicate_names() -> None:
    """Test DBTableSettings with duplicate names."""
    with pytest.raises(ValueError, match="Duplicate table name: 'hosts'"):
        DBTableSettings(
            hosts="hosts",
            hosts_source="hosts",
        )


def test_dbtablesettings_empty_name() -> None:
    """Test DBTableSettings with empty name."""
    with pytest.raises(ValueError, match="empty"):
        DBTableSettings(
            hosts="",
            hosts_source="hosts_source",
        )


def test_garbagecollectorsettings_deprecated_field():
    """Test that garbage collector settings handling deprecated field correctly."""
    # Setting only deprecated field assigns it to new field in subconfig
    settings = ZacSettings(
        source_collector_dir="",
        host_modifier_dir="",
        process=ProcessesSettings(
            garbage_collector=GarbageCollectorSettings(
                update_interval=86400,
                enabled=False,
                delete_empty_maintenance=False,
            )
        ),
    )

    # The subconfig should have been assigned the deprecated main config value
    # because it was explicitly set, while the subconfig was not.
    assert settings.process.garbage_collector.maintenances.delete_empty is False

    # Setting both should use the new field and ignore the deprecated field
    settings = ZacSettings(
        source_collector_dir="",
        host_modifier_dir="",
        process=ProcessesSettings(
            garbage_collector=GarbageCollectorSettings(
                update_interval=86400,
                enabled=False,
                delete_empty_maintenance=False,
                maintenances=MaintenanceGcSettings(delete_empty=True),
            )
        ),
    )
    assert settings.process.garbage_collector.maintenances.delete_empty is True

    # Setting only new should use new (duh)
    settings = ZacSettings(
        source_collector_dir="",
        host_modifier_dir="",
        process=ProcessesSettings(
            garbage_collector=GarbageCollectorSettings(
                update_interval=86400,
                enabled=False,
                maintenances=MaintenanceGcSettings(delete_empty=True),
            )
        ),
    )
    assert settings.process.garbage_collector.maintenances.delete_empty is True
