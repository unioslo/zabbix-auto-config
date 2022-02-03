import logging

from typing import (
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from pydantic import (
    BaseModel,
    conint,
    validator,
)

from . import utils

# TODO: Models aren't validated when making changes to a set/list. Why? How to handle?


class Interface(BaseModel):
    details: Optional[Dict[str, Union[int, str]]] = {}
    endpoint: str
    port: str  # Ports could be macros, i.e. strings
    type: int

    class Config:
        validate_assignment = True

    @validator("type")
    def type_2_must_have_details(cls, v, values):
        if v == 2 and not values["details"]:
            raise ValueError("Interface of type 2 must have details set")
        return v


class Host(BaseModel):
    enabled: bool
    hostname: str

    importance: Optional[conint(ge=0)]
    interfaces: Optional[List[Interface]] = []
    inventory: Optional[Dict[str, str]] = {}
    macros: Optional[None] = None  # TODO: What should macros look like?
    properties: Optional[Set[str]] = set()
    proxy_pattern: Optional[str]
    siteadmins: Optional[Set[str]] = set()
    sources: Optional[Set[str]] = set()
    tags: Optional[Set[Tuple[str, str]]] = set()

    class Config:
        validate_assignment = True

    @validator("interfaces")
    def no_duplicate_interface_types(cls, v):
        types = [interface.type for interface in v]
        assert len(types) == len(set(types)), f"No duplicate interface types: {types}"
        return v

    @validator("proxy_pattern")
    def must_be_valid_regexp_pattern(cls, v):
        if v is not None:
            assert utils.is_valid_regexp(v), f"Must be valid regexp pattern: {v!r}"
        return v

    def merge(self, other):
        """
        Merge other host into this one. The current hostname will be kept if they do not match.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Can't merge with objects of other type: {type(other)}")

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
