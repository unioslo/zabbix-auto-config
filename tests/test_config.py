import os
import unittest
import tomli

import pytest
from pydantic.error_wrappers import ValidationError

import zabbix_auto_config.models as models


def test_sample_config(sample_config):
    models.Settings(**tomli.loads(sample_config))


def test_invalid_config(sample_config):
    config = tomli.loads(sample_config)
    config["foo"] = "bar"
    with pytest.raises(ValidationError) as exc_info:
        models.Settings(**config)
    assert exc_info.value.errors() == [
        {
            "loc": ("foo",),
            "msg": "extra fields not permitted",
            "type": "value_error.extra",
        }
    ]


if __name__ == "__main__":
    unittest.main()
