import unittest
import zabbix_auto_config.models as models

import pytest
from pydantic.error_wrappers import ValidationError

import fixtures

class TestModels(unittest.TestCase):

    @staticmethod
    def find_host_by_hostname(hosts, hostname):
        for host in hosts:
            if host["hostname"].startswith(hostname):
                return host
        return None

    def setUp(self):
        self.minimal_hosts = fixtures.minimal_hosts()
        self.full_hosts = fixtures.full_hosts()
        self.invalid_hosts = fixtures.invalid_hosts()

    def test_minimal_host(self):
        for host in self.minimal_hosts:
            models.Host(**host)

    def test_full_host(self):
        for host in self.full_hosts:
            models.Host(**host)

    def test_invalid_proxy_pattern(self):
        host = self.find_host_by_hostname(self.invalid_hosts, "invalid-proxy-pattern")
        with pytest.raises(ValidationError) as exc_info:
            models.Host(**host)
        assert exc_info.value.errors() == [{'loc': ('proxy_pattern',),
                                            'msg': "Must be valid regexp pattern: '['",
                                            'type': 'assertion_error'}]


    def test_invalid_interface(self):
        host = self.find_host_by_hostname(self.invalid_hosts, "invalid-interface")
        with pytest.raises(ValidationError) as exc_info:
            models.Host(**host)
        assert exc_info.value.errors() == [{'loc': ('interfaces', 0, 'type'),
                                            'msg': 'Interface of type 2 must have details set',
                                            'type': 'value_error'}]

    def test_duplicate_interface(self):
        host = self.find_host_by_hostname(self.invalid_hosts, "duplicate-interface")
        with pytest.raises(ValidationError) as exc_info:
            models.Host(**host)
        assert exc_info.value.errors() == [{'loc': ('interfaces',),
                                            'msg': 'No duplicate interface types: [1, 1]',
                                            'type': 'assertion_error'}]
    def test_invalid_importance(self):
        host = self.find_host_by_hostname(self.invalid_hosts, "invalid-importance")
        with pytest.raises(ValidationError) as exc_info:
            models.Host(**host)
        assert exc_info.value.errors() == [
            {
                "loc": ("importance",),
                "msg": "ensure this value is greater than or equal to 0",
                "type": "value_error.number.not_ge",
                "ctx": {"limit_value": 0},
            }
        ]



if __name__ == "__main__":
    unittest.main()
