from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING
from typing import Optional

from zabbix_auto_config.exceptions import ZabbixAPICallError
from zabbix_auto_config.exceptions import ZabbixNotFoundError
from zabbix_auto_config.pyzabbix.client import ZabbixAPI

if TYPE_CHECKING:
    from zabbix_auto_config.pyzabbix.types import Proxy


def get_random_proxy(client: ZabbixAPI, pattern: Optional[str] = None) -> Proxy:
    """Fetches a random proxy, optionally matching a regex pattern."""
    proxies = client.get_proxies()
    if not proxies:
        raise ZabbixNotFoundError("No proxies found")
    if pattern:
        try:
            re_pattern = re.compile(pattern)
        except re.error:
            raise ZabbixAPICallError(f"Invalid proxy regex pattern: {pattern!r}")
        proxies = [proxy for proxy in proxies if re_pattern.match(proxy.name)]
        if not proxies:
            raise ZabbixNotFoundError(f"No proxies matching pattern {pattern!r}")
    return random.choice(proxies)
