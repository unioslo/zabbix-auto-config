import logging
import tomli

import pytest
from pydantic import Extra
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
