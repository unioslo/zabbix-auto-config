from __future__ import annotations

import zabbix_auto_config.models

HOSTS = [
    {
        "hostname": "foo.example.com",
    },
    {
        "hostname": "bar.example.com",
    },
]


def collect(*args, **kwargs):
    hosts = []
    for host in HOSTS:
        host["enabled"] = True
        host["siteadmins"] = ["bob@example.com"]
        host["properties"] = ["pizza"]
        source = kwargs.get("source")
        if source:
            host["properties"].append(source)
        hosts.append(zabbix_auto_config.models.Host(**host))
    return hosts
