"""Custom types used by Zabbix Auto Config.

Leading underscore in module name to avoid name collision with built-in module `types`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from typing import NamedTuple
from typing import Protocol
from typing import TypedDict
from typing import runtime_checkable

from zabbix_auto_config.models import Host
from zabbix_auto_config.models import SourceCollectorSettings


class ZabbixTag(TypedDict):
    tag: str
    value: str


ZabbixTags = Sequence[ZabbixTag]

ZacTag = tuple[str, str]
ZacTags = set[ZacTag]


@runtime_checkable
class SourceCollectorModule(Protocol):
    """Module that collects hosts from a source."""

    def collect(self, *args: Any, **kwargs: Any) -> list[Host]:
        """Collect hosts from the given source. Returns a list of Host objects"""
        ...


@runtime_checkable
class HostModifierModule(Protocol):
    """Module that modifies a Host object."""

    def modify(self, host: Host) -> Host:
        """Takes a Host object and returns a modified Host object."""
        ...


class HostModifier(NamedTuple):
    """An imported host modifier."""

    name: str
    module: HostModifierModule


class SourceCollector(NamedTuple):
    """The dict created by `zabbix_auto_config.get_source_collectors` for each
    imported source collector module."""

    name: str
    module: SourceCollectorModule
    config: SourceCollectorSettings
