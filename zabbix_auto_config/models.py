import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, ValidationInfo
from pydantic import BaseModel as PydanticBaseModel
from pydantic import (
    ConfigDict,
    Field,
    field_validator,
    field_serializer,
    model_validator,
)
from typing_extensions import Annotated

from . import utils

# TODO: Models aren't validated when making changes to a set/list. Why? How to handle?


class ConfigBaseModel(PydanticBaseModel, extra="ignore"):
    """Base class for all config models. Warns if unknown fields are passed in."""
    # https://pydantic-docs.helpmanual.io/usage/model_config/#change-behaviour-globally

    @model_validator(mode="before")
    @classmethod
    def _check_unknown_fields(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Checks for unknown fields and logs a warning if any are found.
        Does not log warnings if extra is set to `Extra.allow`.
        """
        if cls.model_config["extra"] == "allow":
            return values
        for key in values:
            if key not in cls.model_fields:
                logging.warning(
                    "%s: Got unknown config field '%s'.",
                    getattr(cls, "__name__", str(cls)),
                    key,
                )
        return values


class ZabbixSettings(ConfigBaseModel):
    map_dir: str
    url: str
    username: str
    password: str
    dryrun: bool
    timeout: Optional[int] = Field(
        60,
        description="The timeout in seconds for HTTP requests to Zabbix.",
        ge=0,
    )

    tags_prefix: str = "zac_"
    managed_inventory: List[str] = []
    failsafe: int = 20

    hostgroup_all: str = "All-hosts"
    hostgroup_manual: str = "All-manual-hosts"
    hostgroup_disabled: str = "All-auto-disabled-hosts"

    hostgroup_source_prefix: str = "Source-"
    hostgroup_importance_prefix: str = "Importance-"
    templategroup_prefix: str = "Templates-"

    # Prefixes for extra host groups to create based on the host groups
    # in the siteadmin mapping. 
    # e.g. Siteadmin-foo -> Templates-foo if list is ["Templates-"]
    # The groups must have prefixes separated by a hyphen (-) in order 
    # to replace them with any of these prefixes.
    # These groups are not managed by ZAC beyond creating them.
    extra_siteadmin_hostgroup_prefixes: Set[str] = set()

    @field_validator("timeout")
    @classmethod
    def _validate_timeout(cls, v: Optional[int]) -> Optional[int]:
        if v == 0:
            return None
        return v

class ZacSettings(ConfigBaseModel):
    source_collector_dir: str
    host_modifier_dir: str
    db_uri: str
    log_level: int = Field(logging.DEBUG, description="The log level to use.")
    health_file: Optional[Path] = None
    failsafe_file: Optional[Path] = None
    failsafe_ok_file: Optional[Path] = None
    failsafe_ok_file_strict: bool = True

    @field_validator("health_file", "failsafe_file", "failsafe_ok_file", mode="after")
    @classmethod
    def _validate_file_path(cls, v: Optional[Path], info: ValidationInfo) -> Optional[Path]:
        if v is None:
            return v
        if v.exists() and v.is_dir():
            raise ValueError(f"'{info.field_name}' cannot be a directory")
        if not v.exists():
            utils.make_parent_dirs(v)
        return v

    @field_serializer("log_level")
    def _serialize_log_level(self, v: str) -> str:
        """Serializes the log level as a string.
        Ensures consistent semantics between loading/storing log level in config.
        E.g. we dump `"INFO"` instead of `20`.
        """
        return logging.getLevelName(v)

    @field_validator("log_level", mode="before")
    @classmethod
    def _validate_log_level(cls, v: Any) -> int:
        """Validates the log level and converts it to an integer.
        The log level can be specified as an integer or a string."""
        if isinstance(v, int):
            if v not in logging._levelToName:
                raise ValueError(
                    f"Invalid log level: {v} is not a valid log level integer."
                )
            return v
        elif isinstance(v, str):
            v = v.upper()
            level_int = logging._nameToLevel.get(v, None)
            if level_int is None:
                raise ValueError(
                    f"Invalid log level: {v} is not a valid log level name."
                )
            return level_int
        else:
            raise TypeError("Log level must be an integer or string.")


class SourceCollectorSettings(ConfigBaseModel, extra="allow"):
    module_name: str
    update_interval: int
    error_tolerance: int = Field(
        0,
        description="Number of errors to allow within the last `error_duration` seconds before marking the collector as failing.",
        ge=0,
    )
    error_duration: int = Field(
        0,
        description=(
            "The duration in seconds that errors are stored."
            "If `error_tolerance` errors occur in this period, the collector is marked as failing."
        ),
        ge=0,
    )
    exit_on_error: bool = Field(
        True,
        description="Exit ZAC if the collector failure tolerance is exceeded. Collector is disabled otherwise.",
    )
    disable_duration: int = Field(
        3600,
        description="Duration to disable the collector for if the error tolerance is exceeded. 0 to disable indefinitely.",
        ge=0,
    )

    @model_validator(mode="after")
    def _validate_error_duration_is_greater(self) -> "SourceCollectorSettings":
        # If no tolerance, we don't need to be concerned with how long errors
        # are kept on record, because a single error will disable the collector.
        if self.error_tolerance <= 0:
            # hack to ensure RollingErrorCounter.count() doesn't discard the error
            # before it is counted
            self.error_duration = 9999
        elif (
            product := self.error_tolerance * self.update_interval
        ) > self.error_duration:
            raise ValueError(
                f"Invalid value for error_duration ({self.error_duration}). It should be greater than error_tolerance ({self.error_tolerance}) "
                f"times update_interval ({self.update_interval}), i.e., greater than {product}. Please adjust accordingly."
            )
        return self


class Settings(ConfigBaseModel):
    zac: ZacSettings
    zabbix: ZabbixSettings
    source_collectors: Dict[str, SourceCollectorSettings]


class Interface(BaseModel):
    details: Optional[Dict[str, Union[int, str]]] = {}
    endpoint: str
    port: str  # Ports could be macros, i.e. strings
    type: int
    model_config = ConfigDict(validate_assignment=True)

    @model_validator(mode="after")
    def type_2_must_have_details(self) -> "Interface":
        if self.type == 2 and not self.details:
            raise ValueError("Interface of type 2 must have details set")
        return self


class Host(BaseModel):
    enabled: bool
    hostname: str

    importance: Optional[Annotated[int, Field(ge=0)]] = None
    interfaces: List[Interface] = []
    inventory: Dict[str, str] = {}
    macros: Optional[None] = None  # TODO: What should macros look like?
    properties: Set[str] = set()
    proxy_pattern: Optional[str] = None  # NOTE: replace with Optional[typing.Pattern]?
    siteadmins: Set[str] = set()
    sources: Set[str] = set()
    tags: Set[Tuple[str, str]] = set()
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
    def no_duplicate_interface_types(cls, v: List[Interface]) -> List[Interface]:
        types = [interface.type for interface in v]
        assert len(types) == len(set(types)), f"No duplicate interface types: {types}"
        return v

    @field_validator("proxy_pattern")
    @classmethod
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


class HostActions(BaseModel):
    add: List[str] = []
    remove: List[str] = []

    def write_json(self, path: Path) -> None:
        """Writes a JSON serialized representation of self to a file."""
        utils.write_file(path, self.model_dump_json(indent=2))
