"""Host modifier that modifies a specific host _and_ all hosts."""

from __future__ import annotations

from zabbix_auto_config.models import Host


def modify(host: Host) -> Host:
    if host.hostname == "bar.example.com":
        host.properties.add("barry")
    if not host.proxy_pattern:
        host.proxy_pattern = ".*"
    return host
