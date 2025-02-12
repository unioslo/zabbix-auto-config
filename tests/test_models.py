from __future__ import annotations

import logging
from typing import Optional

import pytest
from inline_snapshot import snapshot
from pydantic import ValidationError
from zabbix_auto_config import models

# NOTE: Do not test msg and ctx of Pydantic errors!
# They are not guaranteed to be stable between minor versions.
# https://docs.pydantic.dev/latest/version-compatibility/#pydantic-v2-changes


def find_host_by_hostname(hosts, hostname):
    for host in hosts:
        if host["hostname"].startswith(hostname):
            return host
    return None


def test_minimal_host(minimal_hosts):
    for host in minimal_hosts:
        models.Host(**host)


def test_full_host(full_hosts):
    for host in full_hosts:
        models.Host(**host)


def test_invalid_proxy_pattern(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-proxy-pattern")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("proxy_pattern",)
    assert "Must be valid regexp pattern: '['" in error["msg"]
    assert error["type"] == "assertion_error"


def test_invalid_interface(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-interface")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("interfaces", 0)
    assert "Interface of type 2 must have details set" in error["msg"]
    assert error["type"] == "value_error"


def test_duplicate_interface(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "duplicate-interface")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("interfaces",)
    assert "No duplicate interface types: [1, 1]" in error["msg"]
    assert error["type"] == "assertion_error"


def test_invalid_importance(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-importance")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("importance",)
    assert error["input"] == -1
    assert error["type"] == "greater_than_equal"


def test_host_merge(full_hosts):
    """Tests Host.merge()"""
    host = find_host_by_hostname(full_hosts, "foo")
    h1 = models.Host(**host)

    host["hostname"] = "bar.example.com"
    host["enabled"] = False
    host["properties"] = {"prop2", "prop3"}
    host["siteadmins"] = {"bob@example.com", "chuck@example.com"}
    host["sources"] = {"source2", "source3"}
    host["tags"] = [["tag2", "y"], ["tag3", "z"]]
    host["importance"] = 2
    # TODO: interfaces
    # TODO: proxy_pattern
    host["inventory"] = {"foo": "bar", "baz": "qux"}
    h2 = models.Host(**host)

    h1.merge(h2)

    assert h1.hostname == "foo.example.com"
    assert h1.enabled
    assert h1.properties == {"prop1", "prop2", "prop3"}
    assert h1.siteadmins == {
        "alice@example.com",
        "bob@example.com",
        "chuck@example.com",
    }
    assert h1.sources == {"source1", "source2", "source3"}
    assert h1.tags == {("tag1", "x"), ("tag2", "y"), ("tag3", "z")}
    assert h1.importance == 1
    assert h1.inventory == {"foo": "bar", "baz": "qux"}


def test_host_merge_invalid(full_hosts):
    """Tests Host.merge() with incorrect argument type"""
    host = find_host_by_hostname(full_hosts, "foo")
    h1 = models.Host(**host)
    with pytest.raises(TypeError):
        h1.merge(object())


DEFAULT_DB_SETTINGS = models.DBSettings(user="zabbix", password="secret")


@pytest.mark.parametrize(
    "level,expect",
    [
        ["notset", logging.NOTSET],
        ["debug", logging.DEBUG],
        ["info", logging.INFO],
        ["warn", logging.WARN],  # noqa: LOG009 # we need to test the deprecated name
        ["warning", logging.WARNING],
        ["error", logging.ERROR],
        ["fatal", logging.FATAL],
        ["critical", logging.CRITICAL],
    ],
)
@pytest.mark.parametrize("upper", [True, False])
def test_zacsettings_log_level_str(level: str, expect: int, upper: bool) -> None:
    settings = models.ZacSettings(
        source_collector_dir="",
        host_modifier_dir="",
        db=DEFAULT_DB_SETTINGS,
        log_level=level.upper() if upper else level.lower(),
    )
    assert settings.log_level == expect


@pytest.mark.parametrize(
    "level,expect",
    [
        [0, logging.NOTSET],
        [10, logging.DEBUG],
        [20, logging.INFO],
        [30, logging.WARN],  # noqa: LOG009 # we need to test the deprecated name
        [30, logging.WARNING],
        [40, logging.ERROR],
        [50, logging.FATAL],
        [50, logging.CRITICAL],
    ],
)
def test_zacsettings_log_level_int(level: str, expect: int) -> None:
    settings = models.ZacSettings(
        source_collector_dir="",
        host_modifier_dir="",
        db=DEFAULT_DB_SETTINGS,
        log_level=level,
    )
    assert settings.log_level == expect


def test_zacsettings_log_level_serialize() -> None:
    settings = models.ZacSettings(
        source_collector_dir="",
        host_modifier_dir="",
        db=DEFAULT_DB_SETTINGS,
        log_level=logging.INFO,
    )
    assert settings.log_level == logging.INFO == 20  # sanity check

    # Serialize to dict:
    settings_dict = settings.model_dump()
    assert settings_dict["log_level"] == "INFO"

    # Serialize to JSON:
    settings_json = settings.model_dump_json()
    assert '"log_level":"INFO"' in settings_json


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
    settings = models.ZabbixSettings(
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
    for strategy in models.FailureStrategy:
        if strategy in (models.FailureStrategy.EXIT, models.FailureStrategy.DISABLE):
            assert strategy.supports_error_tolerance()
        else:
            assert not strategy.supports_error_tolerance()


def _get_zac_settings(config: models.Settings, db_uri: str) -> models.ZacSettings:
    return models.ZacSettings(
        source_collector_dir=config.zac.source_collector_dir,
        host_modifier_dir=config.zac.host_modifier_dir,
        log_level=config.zac.log_level,
        db_uri=db_uri,
        # Omit DBSettings
    )


def test_zacsettings_db_uri_all(config: models.Settings):
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
            "tables": {"hosts": "hosts", "hosts_source": "hosts_source"},
            "init": {"db": False, "tables": True},
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


def test_zacsettings_db_uri_only_required(config: models.Settings):
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
            "tables": {"hosts": "hosts", "hosts_source": "hosts_source"},
            "init": {"db": False, "tables": True},
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


def test_zacsettings_db_uri_extra(config: models.Settings):
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
            "tables": {"hosts": "hosts", "hosts_source": "hosts_source"},
            "init": {"db": False, "tables": True},
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


def test_zacsettings_db_uri_empty_values_and_extras(config: models.Settings):
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
            "tables": {"hosts": "hosts", "hosts_source": "hosts_source"},
            "init": {"db": False, "tables": True},
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


def test_zacsettings_db_uri_missing_all(config: models.Settings):
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
            "tables": {"hosts": "hosts", "hosts_source": "hosts_source"},
            "init": {"db": False, "tables": True},
        }
    )

    assert settings.db.get_connect_kwargs() == snapshot(
        {"dbname": "zac", "host": "localhost", "port": 5432, "connect_timeout": 2}
    )


def test_zacsettings_dbsettings(config: models.Settings) -> None:
    """Test ZacSettings with DBSettings."""
    config.zac.db = models.DBSettings(
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
