"""Host modifier that tags hosts based on their hostname."""

from __future__ import annotations

from zabbix_auto_config.models import Host


def modify(host: Host) -> Host:
    if host.hostname == "foo.example.com":
        host.tags.add(("zac_key", "value"))
        host.tags.add(("zac_tagged", "True"))
        host.tags.add(("non_zac_tag", "yeah"))
    return host
