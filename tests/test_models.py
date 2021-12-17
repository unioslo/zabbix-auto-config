import unittest
import zabbix_auto_config.models as models

import fixtures

class TestModels(unittest.TestCase):

    def setUp(self):
        self.minimal_hosts = fixtures.minimal_hosts()
        self.full_hosts = fixtures.full_hosts()

    def test_minimal_host(self):
        for host in self.minimal_hosts:
            models.Host(**host)

    def test_full_host(self):
        for host in self.full_hosts:
            models.Host(**host)

if __name__ == "__main__":
    unittest.main()
