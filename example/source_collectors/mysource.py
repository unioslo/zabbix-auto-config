from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List

from zabbix_auto_config.models import Host

HOSTS: List[Dict[str, Any]] = [
    {
        "hostname": "foo.example.com",
        "siteadmins": ["alice@example.com"],
    },
    {
        "hostname": "bar.example.com",
        "siteadmins": ["bob@example.com"],
    },
    {
        "hostname": "baz.example.com",
        "siteadmins": ["charlie@example.com", "david@example.com"],
    },
]


def collect(*args: Any, **kwargs: Any) -> List[Host]:
    hosts: List[Host] = []
    for host in HOSTS:
        host["enabled"] = True
        host["properties"] = ["pizza"]

        # We can access arbitrary extra options from the config
        # via the `kwargs` dict
        kwarg_from_config = kwargs.get("kwarg_from_config")
        if kwarg_from_config:
            host["properties"].append(kwarg_from_config)

        # Mark collected hosts as coming from "mysource"
        host["source"] = "mysource"

        # Only hostname and enabled are required.
        # See `zabbix_auto_config.models.Host` for all available fields.
        hosts.append(Host(**host))
    return hosts


if __name__ == "__main__":
    # When run as a script, print the collected hosts
    from zabbix_auto_config.models import print_hosts

    print_hosts(collect())
