"""Custom types used by Zabbix Auto Config.

Leading underscore in module name to avoid name collision with built-in module `types`.
"""

from __future__ import annotations

from typing import Any
from typing import List
from typing import Protocol
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import TypedDict
from typing import runtime_checkable

from .models import Host
from .models import SourceCollectorSettings


class ZabbixTag(TypedDict):
    tag: str
    value: str


ZabbixTags = Sequence[ZabbixTag]

ZacTag = Tuple[str, str]
ZacTags = Set[ZacTag]


@runtime_checkable
class SourceCollectorModule(Protocol):
    """Module that collects hosts from a source."""

    def collect(self, *args: Any, **kwargs: Any) -> List[Host]:
        """Collect hosts from the given source. Returns a list of Host objects"""
        ...


@runtime_checkable
class HostModifierModule(Protocol):
    """Module that modifies a Host object."""

    def modify(self, host: Host) -> Host:
        """Takes a Host object and returns a modified Host object."""
        ...


class HostModifierDict(TypedDict):
    """The dict created by
    `zabbix_auto_config.processing.SourceMergerProcess.get_host_modifiers`
    for each imported host modifier module."""

    name: str
    module: HostModifierModule


class SourceCollectorDict(TypedDict):
    """The dict created by `zabbix_auto_config.get_source_collectors` for each
    imported source collector module."""

    name: str
    module: SourceCollectorModule
    config: SourceCollectorSettings


class QueueDict(TypedDict):
    """Queue information for the health check dict."""

    size: int


class HealthDict(TypedDict):
    """Application health dict used by `zabbix_auto_config.__init__.write_health`"""

    date: str
    date_unixtime: int
    pid: int
    cwd: str
    all_ok: bool
    processes: List[dict]
    queues: List[QueueDict]
    failsafe: int
