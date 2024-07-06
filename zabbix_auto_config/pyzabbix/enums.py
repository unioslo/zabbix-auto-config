from __future__ import annotations

from enum import IntEnum

from zabbix_auto_config.exceptions import ZACException


class UserRole(IntEnum):
    USER = 1
    ADMIN = 2
    SUPERADMIN = 3
    GUEST = 4


class UsergroupPermission(IntEnum):
    """Usergroup permission levels."""

    DENY = 0
    READ_ONLY = 2
    READ_WRITE = 3


class AgentAvailable(IntEnum):
    """Agent availability status."""

    UNKNOWN = 0
    AVAILABLE = 1
    UNAVAILABLE = 2


class MonitoringStatus(IntEnum):
    """Host monitoring status."""

    ON = 0  # Yes, 0 is on, 1 is off...
    OFF = 1


class MaintenanceStatus(IntEnum):
    """Host maintenance status."""

    # API values are inverted here compared to monitoring status...
    ON = 1
    OFF = 0


class InventoryMode(IntEnum):
    """Host inventory mode."""

    DISABLED = -1
    MANUAL = 0
    AUTOMATIC = 1


class GUIAccess(IntEnum):
    """GUI Access for a user group."""

    DEFAULT = 0
    INTERNAL = 1
    LDAP = 2
    DISABLE = 3


class DataCollectionMode(IntEnum):
    """Maintenance type."""

    ON = 0
    OFF = 1


class TriggerPriority(IntEnum):
    UNCLASSIFIED = 0
    INFORMATION = 1
    WARNING = 2
    AVERAGE = 3
    HIGH = 4
    DISASTER = 5


class InterfaceConnectionMode(IntEnum):
    """Interface connection mode.

    Controls the value of `useip` when creating interfaces in the API.
    """

    DNS = 0
    IP = 1


class InterfaceType(IntEnum):
    """Interface type."""

    AGENT = 1
    SNMP = 2
    IPMI = 3
    JMX = 4

    def get_port(self: InterfaceType) -> str:
        """Returns the default port for the given interface type."""
        PORTS = {
            InterfaceType.AGENT: "10050",
            InterfaceType.SNMP: "161",
            InterfaceType.IPMI: "623",
            InterfaceType.JMX: "12345",
        }
        try:
            return PORTS[self]
        except KeyError:
            raise ZACException(f"Unknown interface type: {self}")


class SNMPSecurityLevel(IntEnum):
    __choice_name__ = "SNMPv3 security level"

    # Match casing from Zabbix API
    NO_AUTH_NO_PRIV = 0
    AUTH_NO_PRIV = 1
    AUTH_PRIV = 2


class SNMPAuthProtocol(IntEnum):
    """Authentication protocol for SNMPv3."""

    MD5 = 0
    SHA1 = 1
    # >=6.0 only:
    SHA224 = 2
    SHA256 = 3
    SHA384 = 4
    SHA512 = 5


class SNMPPrivProtocol(IntEnum):
    """Privacy protocol for SNMPv3."""

    DES = 0
    AES = 1  # < 6.0 only
    # >=6.0 only:
    AES128 = 1  # >= 6.0
    AES192 = 2
    AES256 = 3
    AES192C = 4
    AES256C = 5
