import logging

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from pydantic import (
    BaseModel,
    BaseSettings,
    conint,
    root_validator,
    validator,
    Extra,
)
from pydantic.fields import ModelField

from . import utils

# TODO: Models aren't validated when making changes to a set/list. Why? How to handle?


class ZabbixSettings(BaseSettings):
    map_dir: str
    url: str
    username: str
    password: str
    dryrun: bool

    tags_prefix: str = "zac_"
    managed_inventory: List[str] = []
    failsafe: int = 20

    hostgroup_all: str = "All-hosts"
    hostgroup_manual: str = "All-manual-hosts"
    hostgroup_disabled: str = "All-auto-disabled-hosts"

    hostgroup_source_prefix: str = "Source-"
    hostgroup_importance_prefix: str = "Importance-"

    # Prefixes for extra host groups to create based on the host groups
    # in the siteadmin mapping. 
    # e.g. Siteadmin-foo -> Templates-foo if list is ["Templates-"]
    # The groups must have prefixes separated by a hyphen (-) in order 
    # to replace them with any of these prefixes.
    # These groups are not managed by ZAC beyond creating them.
    extra_siteadmin_hostgroup_prefixes: Set[str] = set()

class ZacSettings(BaseSettings):
    source_collector_dir: str
    host_modifier_dir: str
    db_uri: str

    health_file: str = None


class SourceCollectorSettings(BaseSettings, extra=Extra.allow):
    module_name: str
    update_interval: int


class Settings(BaseSettings):
    zac: ZacSettings
    zabbix: ZabbixSettings
    source_collectors: Dict[str, SourceCollectorSettings]


class Interface(BaseModel):
    details: Optional[Dict[str, Union[int, str]]] = {}
    endpoint: str
    port: str  # Ports could be macros, i.e. strings
    type: int

    class Config:
        validate_assignment = True

    # These validators look static, but pydantic uses the class argument.
    # pylint: disable=no-self-use, no-self-argument
    @validator("type")
    def type_2_must_have_details(cls, v, values):
        if v == 2 and not values["details"]:
            raise ValueError("Interface of type 2 must have details set")
        return v


class Host(BaseModel):
    enabled: bool
    hostname: str

    importance: Optional[conint(ge=0)]  # type: ignore # mypy blows up: https://github.com/pydantic/pydantic/issues/239 & https://github.com/pydantic/pydantic/issues/156
    interfaces: List[Interface] = []
    inventory: Dict[str, str] = {}
    macros: Optional[None] = None  # TODO: What should macros look like?
    properties: Set[str] = set()
    proxy_pattern: Optional[str]  # NOTE: replace with Optional[typing.Pattern]?
    siteadmins: Set[str] = set()
    sources: Set[str] = set()
    tags: Set[Tuple[str, str]] = set()

    class Config:
        validate_assignment = True

    # pylint: disable=no-self-use, no-self-argument
    @validator("*", pre=True)
    def none_defaults_to_field_default(cls, v: Any, field: ModelField) -> Any:
        """The field's default value or factory is returned if the value is None."""
        # TODO: add field type check
        if v is None:
            if field.default is not None:
                return field.default
            elif field.default_factory is not None:
                return field.default_factory()
        return v

    # pylint: disable=no-self-use, no-self-argument
    @validator("interfaces")
    def no_duplicate_interface_types(cls, v: List[Interface]) -> List[Interface]:
        types = [interface.type for interface in v]
        assert len(types) == len(set(types)), f"No duplicate interface types: {types}"
        return v

    # pylint: disable=no-self-use, no-self-argument
    @validator("proxy_pattern")
    def must_be_valid_regexp_pattern(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            assert utils.is_valid_regexp(v), f"Must be valid regexp pattern: {v!r}"
        return v

    def merge(self, other: "Host") -> None:
        """
        Merge other host into this one. The current hostname will be kept if they do not match.
        """
        if not isinstance(other, self.__class__):
            raise TypeError(f"Can't merge with objects of other type: {type(other)}")

        self.enabled = self.enabled or other.enabled
        # self.macros TODO
        self.properties.update(other.properties)
        self.siteadmins.update(other.siteadmins)
        self.sources.update(other.sources)
        self.tags.update(other.tags)

        importances = [importance for importance in [self.importance, other.importance] if importance]
        self.importance = min(importances) if importances else None

        self_interface_types = {i.type for i in self.interfaces}
        for other_interface in other.interfaces:
            if other_interface.type not in self_interface_types:
                self.interfaces.append(other_interface)
            else:
                logging.warning("Trying to merge host with interface of same type. The other interface is ignored. Host: %s, type: %s", self.hostname, other_interface.type)
        self.interfaces = sorted(self.interfaces, key=lambda interface: interface.type)

        for k, v in other.inventory.items():
            if k in self.inventory and v != self.inventory[k]:
                logging.warning("Same inventory ('%s') set multiple times for host: '%s'", k, self.hostname)
            else:
                self.inventory[k] = v

        proxy_patterns = [proxy_pattern for proxy_pattern in [self.proxy_pattern, other.proxy_pattern] if proxy_pattern]
        if len(proxy_patterns) > 1:
            logging.warning("Multiple proxy patterns are provided. Discarding down to one. Host: %s", self.hostname)
            # TODO: Do something different? Is alphabetically first "good enough"? It will be consistent at least.
            self.proxy_pattern = sorted(list(proxy_patterns))[0]
        elif len(proxy_patterns) == 1:
            self.proxy_pattern = proxy_patterns.pop()
