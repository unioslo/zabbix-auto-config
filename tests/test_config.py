from __future__ import annotations

import logging

import pytest
import tomli
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from inline_snapshot import snapshot
from pydantic import ValidationError

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
    original_extra = models.Settings.model_config["extra"]
    try:
        models.Settings.model_config["extra"] = "allow"
        models.Settings(**config)
        assert len(caplog.records) == 0
    finally:
        models.Settings.model_config["extra"] = original_extra


def test_sourcecollectorsettings_defaults():
    # Default setting should be valid
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
    )
    assert settings.module_name == "foo"
    assert settings.update_interval == 60
    assert settings.error_duration > 0
    assert settings.error_tolerance == 0
    assert settings.exit_on_error is True
    assert settings.disable_duration == 3600


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
    assert settings.error_tolerance == 0
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
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert "greater than 300" in error["msg"]
    assert error["type"] == "value_error"
    assert error["msg"] == snapshot(
        "Value error, Invalid value for error_duration (180). It should be greater than 300: error_tolerance (5) * update_interval (60)"
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
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("error_duration",)
    assert error["type"] == "greater_than_equal"
