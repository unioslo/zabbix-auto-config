from __future__ import annotations

from zabbix_auto_config.models import Host


def modify(host: Host) -> Host:
    if host.hostname == "bar.example.com":
        host.properties.add("barry")
    return host
