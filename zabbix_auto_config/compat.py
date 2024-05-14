"""Compatibility functions to support different Zabbix API versions."""

from __future__ import annotations

from typing import Literal

from packaging.version import Version

# Compatibility methods for Zabbix API objects properties and method parameters.
# Returns the appropriate property name for the given Zabbix version.
#
# FORMAT: <object>_<property>
# EXAMPLE: user_name() (User object, name property)
#
# NOTE: All functions follow the same pattern:
# Early return if the version is older than the version where the property
# was deprecated, otherwise return the new property name as the default.


def host_proxyid(version: Version) -> Literal["proxy_hostid", "proxyid"]:
    # https://support.zabbix.com/browse/ZBXNEXT-8500
    # https://www.zabbix.com/documentation/7.0/en/manual/api/changes#host
    if version.release < (7, 0, 0):
        return "proxy_hostid"
    return "proxyid"


def host_hostgroups(version: Version) -> Literal["groups", "hostgroups"]:
    # https://support.zabbix.com/browse/ZBXNEXT-2592
    # https://www.zabbix.com/documentation/6.2/en/manual/api/changes_6.0_-_6.2#host
    if version.release < (6, 2, 0):
        return "groups"
    return "hostgroups"


def proxy_name(version: Version) -> Literal["host", "name"]:
    # https://support.zabbix.com/browse/ZBXNEXT-8500
    # https://www.zabbix.com/documentation/7.0/en/manual/api/changes#proxy
    if version.release < (7, 0, 0):
        return "host"
    return "name"


def proxy_operating_mode(version: Version) -> Literal["status", "operating_mode"]:
    # https://support.zabbix.com/browse/ZBXNEXT-8500
    # https://www.zabbix.com/documentation/7.0/en/manual/api/changes#proxy
    if version.release < (7, 0, 0):
        return "status"
    return "operating_mode"


### API params
# API parameter functions are in the following format:
# param_<object>_<method>_<param>
# So to get the "groups" parameter for the "host.get" method, you would call:
# param_host_get_groups()


def param_host_get_groups(
    version: Version,
) -> Literal["selectHostGroups", "selectGroups"]:
    # https://support.zabbix.com/browse/ZBXNEXT-2592
    # hhttps://www.zabbix.com/documentation/6.2/en/manual/api/changes_6.0_-_6.2#host
    if version.release < (6, 2, 0):
        return "selectGroups"
    return "selectHostGroups"


### Other compatibility functions


def templategroups_supported(version: Version) -> bool:
    """Return True if templategroups are supported in the given Zabbix version."""
    return version.release >= (6, 2, 0)
