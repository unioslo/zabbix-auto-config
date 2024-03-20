from zabbix_auto_config._types import HostModifierModule, SourceCollectorModule
from .data import (
    host_modifier_typed,
    host_modifier_untyped,
    source_collector_typed,
    source_collector_untyped,
)


def test_host_modifier_typed() -> None:
    assert isinstance(host_modifier_typed, HostModifierModule)


def test_host_modifier_untyped() -> None:
    assert isinstance(host_modifier_untyped, HostModifierModule)


def test_source_collector_typed() -> None:
    assert isinstance(source_collector_typed, SourceCollectorModule)


def test_source_collector_untyped() -> None:
    assert isinstance(source_collector_untyped, SourceCollectorModule)
