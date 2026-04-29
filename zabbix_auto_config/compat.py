"""Compatibility functions to support different Zabbix API versions."""

from __future__ import annotations

from packaging.version import Version


def templategroups_supported(version: Version) -> bool:
    """Return True if templategroups are supported in the given Zabbix version."""
    return version.release >= (6, 2, 0)
