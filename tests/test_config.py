import os
import unittest
import tomli

import pytest
from pydantic.error_wrappers import ValidationError

import zabbix_auto_config.models as models

class TestConfig(unittest.TestCase):
    @staticmethod
    def get_sample_config():
        with open(os.path.dirname(os.path.dirname(__file__)) +
                  "/config.sample.toml") as config:
            return config.read()

    def setUp(self):
        self.sample_config = self.get_sample_config()

    def test_sample_config(self):
        models.Settings(**tomli.loads(self.sample_config))

    def test_invalid_config(self):
        config = tomli.loads(self.sample_config)
        config["foo"] = "bar"
        with pytest.raises(ValidationError) as exc_info:
            models.Settings(**config)
        assert exc_info.value.errors() == [{'loc': ('foo',),
                                            'msg': 'extra fields not permitted',
                                            'type': 'value_error.extra'}]


if __name__ == "__main__":
    unittest.main()
