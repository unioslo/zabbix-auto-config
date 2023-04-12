import os
from pathlib import Path
from typing import Iterable
import pytest


@pytest.fixture(scope="function")
def minimal_hosts():
    yield [
        {
            "enabled": True,
            "hostname": "foo.example.com",
        },
    ]


@pytest.fixture(scope="function")
def full_hosts():
    yield [
        {
            "enabled": True,
            "hostname": "foo.example.com",
            "importance": 1,
            "interfaces": [
                {
                    "endpoint": "foo.example.com",
                    "port": "10050",
                    "type": 1,
                },
                {
                    "endpoint": "foo.example.com",
                    "details": {
                        "version": 2,
                        "community": "{$SNMP_COMMUNITY}",
                    },
                    "port": "161",
                    "type": 2,
                },
            ],
            "inventory": None,
            "macros": None,
            "properties": {"prop1", "prop2"},
            "proxy_pattern": r"^zbx-proxy\d+\.example\.com$",
            "siteadmins": {"bob@example.com", "alice@example.com"},
            "sources": {"source1", "source2"},
            "tags": [["tag1", "x"], ["tag2", "y"]],
        },
    ]


@pytest.fixture(scope="function")
def invalid_hosts():
    yield [
        {
            "enabled": True,
            "hostname": "invalid-proxy-pattern.example.com",
            "proxy_pattern": "[",
        },
        {
            "enabled": True,
            "hostname": "invalid-interface.example.com",
            "interfaces": [
                {
                    "endpoint": "type-2-sans-details.example.com",
                    "port": "10050",
                    "type": 2,
                },
            ],
        },
        {
            "enabled": True,
            "hostname": "duplicate-interface.example.com",
            "interfaces": [
                {
                    "endpoint": "endpoint1.example.com",
                    "port": "10050",
                    "type": 1,
                },
                {
                    "endpoint": "endpoint2.example.com",
                    "port": "10050",
                    "type": 1,
                },
            ],
        },
        {
            "enabled": True,
            "hostname": "invalid-importance.example.com",
            "importance": -1,
        },
    ]


@pytest.fixture(scope="function")
def sample_config():
    with open(
        os.path.dirname(os.path.dirname(__file__)) + "/config.sample.toml"
    ) as config:
        yield config.read()


@pytest.fixture
def hostgroup_map_file(tmp_path: Path) -> Iterable[Path]:
    contents = hostgroup_map = """
# This file defines assosiation between siteadm fetched from Nivlheim and hostsgroups in Zabbix.
# A siteadm can be assosiated only with one hostgroup or usergroup.
# Example: <siteadm>:<host/user groupname>
#
#****************************************************************************************
# ATT: First letter will be capitilazed, leading and trailing spaces will be removed and 
#      spaces within the hostgroupname will be replaced with "-" by the script automatically 
#****************************************************************************************
#
user1@example.com:Hostgroup-user1-primary
#
user2@example.com:Hostgroup-user2-primary
user2@example.com:Hostgroup-user2-secondary
#
user3@example.com:Hostgroup-user3-primary
"""
    map_file_path = tmp_path / "siteadmin_hostgroup_map.txt"
    map_file_path.write_text(contents)
    yield map_file_path