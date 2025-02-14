"""Host modifier that modifies a specific host _and_ all hosts."""

from __future__ import annotations

from zabbix_auto_config.models import Host


def modify(host: Host) -> Host:
    if host.hostname == "bar.example.com":
        host.properties.add("barry")
    host.proxy_pattern = ".*"
    return host
