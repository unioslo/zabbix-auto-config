from typing import Any, List
from zabbix_auto_config.models import Host

HOSTS = [
    {
        "hostname": "foo.example.com",
    },
    {
        "hostname": "bar.example.com",
    },
]


def collect(*args: Any, **kwargs: Any) -> List[Host]:
    hosts = []
    for host in HOSTS:
        host["enabled"] = True
        host["siteadmins"] = ["bob@example.com"]
        host["properties"] = ["pizza"]
        source = kwargs.get("source")
        if source:
            host["properties"].append(source)
        hosts.append(Host(**host))
    return hosts
