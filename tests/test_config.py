import logging
import tomli

import pytest
from pydantic import Extra, ValidationError
import zabbix_auto_config.models as models


def test_sample_config(sample_config: str):
    models.Settings(**tomli.loads(sample_config))


def test_config_extra_field(sample_config: str, caplog: pytest.LogCaptureFixture):
    config = tomli.loads(sample_config)
    config["foo"] = "bar"
    models.Settings(**config)
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelname == "WARNING"
    assert record.levelno == logging.WARNING
    assert "'foo'" in record.message


def test_config_extra_field_allowed(
    sample_config: str, caplog: pytest.LogCaptureFixture
):
    config = tomli.loads(sample_config)
    config["foo"] = "bar"

    # Allow extra fields for this test
    original_extra = models.Settings.__config__.extra
    try:
        models.Settings.__config__.extra = Extra.allow
        models.Settings(**config)
        assert len(caplog.records) == 0
    finally:
        models.Settings.__config__.extra = original_extra


def test_source_collector_settings_defaults():
    # Default setting should be valid
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
    )
    assert settings.module_name == "foo"
    assert settings.update_interval == 60


def test_source_collector_settings_no_error_tolerance():
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_tolerance=0,
    )
    assert settings.error_tolerance == 0


def test_source_collector_settings_no_error_interval():
    # In order to not have an error_interval, error_tolerance must be 0 too
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_interval=0,
        error_tolerance=0,
    )
    assert settings.error_interval == 0
    assert settings.error_tolerance == 0

    # With tolerance raises an error
    # NOTE: we test the error message in depth in test_source_collector_settings_invalid_error_interval
    with pytest.raises(ValidationError):
        models.SourceCollectorSettings(
            module_name="foo",
            update_interval=60,
            error_interval=0,
            error_tolerance=5,
        )


def test_source_collector_settings_invalid_error_interval():
    # Error_interval should be greater or equal to the product of
    # error_tolerance and update_interval
    with pytest.raises(ValidationError) as exc_info:
        models.SourceCollectorSettings(
            module_name="foo",
            update_interval=60,
            error_tolerance=5,
            error_interval=180,
        )
    assert exc_info.value.errors() == [
        {
            "loc": ("error_interval",),
            "msg": "error_interval must be greater than or equal to the product of update_interval and error_tolerance (300)",
            "type": "value_error",
        }
    ]


