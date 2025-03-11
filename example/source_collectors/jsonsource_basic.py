from __future__ import annotations

import json
from typing import Any
from typing import List

from zabbix_auto_config.models import Host

DEFAULT_FILE = "hosts.json"


def collect(*args: Any, **kwargs: Any) -> List[Host]:
    filename = kwargs.get("filename", DEFAULT_FILE)
    with open(filename, "r") as f:
        return [Host(**host) for host in json.load(f)]
