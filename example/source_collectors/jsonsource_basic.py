from __future__ import annotations

import json
from typing import Any

from zabbix_auto_config.models import Host

DEFAULT_FILE = "hosts.json"


def collect(*args: Any, **kwargs: Any) -> list[Host]:
    filename = kwargs.get("filename", DEFAULT_FILE)
    with open(filename) as f:
        return [Host(**host) for host in json.load(f)]
