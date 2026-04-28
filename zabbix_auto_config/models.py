from __future__ import annotations

import datetime
from pathlib import Path
from typing import Annotated
from typing import Any
from typing import Optional
from typing import Union

import structlog
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import RootModel
from pydantic import field_validator
from pydantic import model_validator
from typing_extensions import Self

from zabbix_auto_config import utils

logger = structlog.stdlib.get_logger(__name__)


class Interface(BaseModel):
    details: Optional[dict[str, Union[int, str]]] = {}
    endpoint: str
    port: str  # Ports could be macros, i.e. strings
    type: int
    model_config = ConfigDict(validate_assignment=True)

    @model_validator(mode="after")
    def type_2_must_have_details(self) -> Self:
        if self.type == 2 and not self.details:
            raise ValueError("Interface of type 2 must have details set")
        return self


class Host(BaseModel):
    """A host collected by ZAC.

    Not to be confused with `zabbix_auto_config.pyzabbix.types.Host`,
    which is a Zabbix host fetched from the Zabbix API.
    This model represents a host collected from various sources
    before it is turned into a Zabbix host."""

    # Required fields
    enabled: bool
    hostname: str
    # Optional fields
    importance: Optional[Annotated[int, Field(ge=0)]] = None
    interfaces: list[Interface] = []
    inventory: dict[str, str] = {}
    macros: Optional[Any] = None
    properties: set[str] = set()
    proxy_pattern: Optional[str] = None
    siteadmins: set[str] = set()
    sources: set[str] = set()
    tags: set[tuple[str, str]] = set()

    model_config = ConfigDict(validate_assignment=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def none_defaults_to_field_default(cls, data: Any) -> Any:
        """The field's default value or factory is used if the value is None."""
        # TODO: add field type check
        if not isinstance(data, dict):
            return data  # pydantic will handle the error
        for field_name, value in data.items():
            if value is None:
                field = cls.model_fields[field_name]
                if field.default is not None:
                    data[field_name] = field.default
                elif field.default_factory is not None:
                    data[field_name] = field.default_factory()
        return data

    @field_validator("interfaces")
    @classmethod
    def no_duplicate_interface_types(cls, v: list[Interface]) -> list[Interface]:
        types = [interface.type for interface in v]
        assert len(types) == len(set(types)), f"No duplicate interface types: {types}"
        return v

    @field_validator("proxy_pattern")
    @classmethod
    def must_be_valid_regexp_pattern(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            assert utils.is_valid_regexp(v), f"Must be valid regexp pattern: {v!r}"
        return v

    def merge(self, other: Host) -> None:
        """
        Merge other host into this one. The current hostname will be kept if they do not match.
        """
        if not isinstance(other, self.__class__):
            raise TypeError(f"Can't merge with objects of other type: {type(other)}")

        log = logger.bind(host=self.hostname)

        self.enabled = self.enabled or other.enabled
        # self.macros TODO
        self.properties.update(other.properties)
        self.siteadmins.update(other.siteadmins)
        self.sources.update(other.sources)
        self.tags.update(other.tags)

        importances = [
            importance
            for importance in [self.importance, other.importance]
            if importance
        ]
        self.importance = min(importances) if importances else None

        self_interface_types = {i.type for i in self.interfaces}
        for other_interface in other.interfaces:
            if other_interface.type not in self_interface_types:
                self.interfaces.append(other_interface)
            else:
                log.warning(
                    "Trying to merge host with interface of same type. The other interface is ignored",
                    interface_type=other_interface.type,
                )
        self.interfaces = sorted(self.interfaces, key=lambda interface: interface.type)

        for k, v in other.inventory.items():
            if k in self.inventory and v != self.inventory[k]:
                log.warning(
                    "Same inventory key set multiple times for host",
                    inventory_key=k,
                )
            else:
                self.inventory[k] = v

        proxy_patterns = [
            proxy_pattern
            for proxy_pattern in [self.proxy_pattern, other.proxy_pattern]
            if proxy_pattern
        ]
        if len(proxy_patterns) > 1:
            # TODO: Do something different? Is alphabetically first "good enough"? It will be consistent at least.
            self.proxy_pattern = sorted(proxy_patterns)[0]
            log.warning(
                "Multiple proxy patterns are provided. Discarding down to one",
                proxy_pattern=self.proxy_pattern,
            )
        elif len(proxy_patterns) == 1:
            self.proxy_pattern = proxy_patterns.pop()


class HostActions(BaseModel):
    add: list[str] = []
    remove: list[str] = []

    def write_json(self, path: Path) -> None:
        """Writes a JSON serialized representation of self to a file."""
        utils.write_file(path, self.model_dump_json(indent=2))


class HostsSerializer(RootModel[list[Host]]):
    root: list[Host]


def hosts_to_json(hosts: list[Host], indent: int = 2) -> str:
    """Convert a list of Host objects to a JSON string."""
    return HostsSerializer(root=hosts).model_dump_json(indent=indent)


def print_hosts(hosts: list[Host], indent: int = 2) -> None:
    """Print a list of Host objects to stdout as JSON."""
    print(hosts_to_json(hosts, indent=indent))


class HostPendingDeletion(BaseModel):
    """A disabled host that is pending deletion.

    Used by garbage collector to keep track of disabled hosts and when to delete them.
    """

    host_id: str
    hostname: str
    disabled_at: datetime.datetime
