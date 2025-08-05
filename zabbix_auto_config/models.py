from __future__ import annotations

import logging
import re
import warnings
from enum import Enum
from pathlib import Path
from typing import Annotated
from typing import Any
from typing import Optional
from typing import Union

import structlog
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import GetCoreSchemaHandler
from pydantic import RootModel
from pydantic import ValidationInfo
from pydantic import field_validator
from pydantic import model_validator
from pydantic_core import core_schema
from typing_extensions import Self

from zabbix_auto_config import utils
from zabbix_auto_config.dirs import LOG_FILE_DEFAULT

logger = structlog.stdlib.get_logger(__name__)

# TODO: Models aren't validated when making changes to a set/list. Why? How to handle?


class ConfigBaseModel(BaseModel):
    """Base class for all config models. Warns if unknown fields are passed in."""

    # https://pydantic-docs.helpmanual.io/usage/model_config/#change-behaviour-globally

    model_config = ConfigDict(
        # We support overriding values via CLI args, so we want to be able
        # to validate them using the same validation logic we use for config
        # values loaded from files.
        validate_assignment=True,
        # Ignore extra values by default and emit warning if present.
        # Subclasses may override this to allow extra values.
        extra="ignore",
    )

    @model_validator(mode="before")
    @classmethod
    def _check_unknown_fields(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Checks for unknown fields and logs a warning if any are found.
        Does not log warnings if extra is set to `Extra.allow`.
        """
        if cls.model_config.get("extra") == "allow":
            return values
        for key in values:
            if key not in cls.model_fields:
                logger.warning(
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
    verify_ssl: Union[bool, Path] = True
    """Path to a CA bundle file or `True` to use the system's CA bundle. False to disable SSL verification."""

    tags_prefix: str = "zac_"
    managed_inventory: list[str] = []
    failsafe: int = 20

    hostgroup_all: str = "All-hosts"
    hostgroup_manual: str = "All-manual-hosts"
    hostgroup_disabled: str = "All-auto-disabled-hosts"

    hostgroup_source_prefix: str = "Source-"
    hostgroup_importance_prefix: str = "Importance-"

    create_templategroups: bool = False
    templategroup_prefix: str = "Templates-"

    # Prefixes for extra host groups to create based on the host groups
    # in the siteadmin mapping.
    # e.g. Siteadmin-foo -> Secondary-foo if list is ["Secondary-"]
    # The groups must have prefixes separated by a hyphen (-) in order
    # to replace them with any of these prefixes.
    # These groups are not managed by ZAC beyond their creation.
    extra_siteadmin_hostgroup_prefixes: set[str] = set()

    prefix_separator: str = "-"

    @field_validator("timeout")
    @classmethod
    def _validate_timeout(cls, v: Optional[int]) -> Optional[int]:
        if v == 0:
            return None
        return v


class ZabbixHostSettings(ConfigBaseModel):
    remove_from_maintenance: bool = False
    """Remove a host from all its maintenances when disabling it"""


class ProcessSettings(ConfigBaseModel):
    update_interval: int = Field(default=60, ge=0)


# TODO: Future expansion of individual process settings
class SourceMergerSettings(ProcessSettings):
    pass


class HostUpdaterSettings(ProcessSettings):
    pass


class HostGroupUpdaterSettings(ProcessSettings):
    pass


class TemplateUpdaterSettings(ProcessSettings):
    pass


class GarbageCollectorSettings(ProcessSettings):
    enabled: bool = False
    """Remove disabled hosts from maintenances and triggers."""
    delete_empty_maintenance: bool = False
    """Delete maintenance periods if they are empty after removing disabled hosts."""


class ProcessesSettings(ConfigBaseModel):
    """Settings for the various ZAC processes"""

    source_merger: SourceMergerSettings = SourceMergerSettings()
    host_updater: HostUpdaterSettings = HostUpdaterSettings()
    hostgroup_updater: HostGroupUpdaterSettings = HostGroupUpdaterSettings()
    template_updater: TemplateUpdaterSettings = TemplateUpdaterSettings()
    garbage_collector: GarbageCollectorSettings = GarbageCollectorSettings(
        update_interval=86400  # every 24 hours
    )


class DBTableSettings(ConfigBaseModel):
    hosts: str = Field(default="hosts")
    hosts_source: str = Field(default="hosts_source")

    @model_validator(mode="after")
    def _validate_table_names(self) -> Self:
        """Ensure table names are not empty."""
        names: set[str] = set()
        for field in self.__class__.model_fields:
            name = getattr(self, field)
            if not name:
                raise ValueError(
                    f"Config option `zac.db.tables.{field}` cannot be empty"
                )
            if name in names:
                raise ValueError(f"Duplicate table name: {name!r}")
            names.add(name)
        return self


class DBInitSettings(ConfigBaseModel):
    """Settings for controlling database initialization."""

    db: bool = Field(default=True)
    """Create the database if it doesn't exist."""

    tables: bool = Field(default=True)
    """Create tables if they don't exist."""


class DBSettings(ConfigBaseModel):
    """Settings for the database connection."""

    user: str = Field(default="")
    password: str = Field(default="")
    dbname: str = Field(default="zac")
    host: str = Field(default="localhost")
    port: int = Field(default=5432)
    connect_timeout: int = Field(default=2)

    # Table names
    tables: DBTableSettings = Field(default_factory=DBTableSettings)
    # Initialization settings
    init: DBInitSettings = Field(default_factory=DBInitSettings)

    # ZacSettings Validator mutates model, check assigned values
    model_config = ConfigDict(
        # Validate values assigned by ZacSettings validator
        validate_assignment=True,
        # Pass extra keys to psycopg2.connect as kwargs
        extra="allow",
    )

    def get_connect_kwargs(self) -> dict[str, Any]:
        """Return kwargs for psycopg2.connect.

        Only include non-empty values."""
        kwargs = {
            "dbname": self.dbname,
            "user": self.user,
            "password": self.password,
            "host": self.host,
            "port": self.port,
            "connect_timeout": self.connect_timeout,
            **self.extra_kwargs(),
        }
        return {k: v for k, v in kwargs.items() if v}

    def extra_kwargs(self) -> dict[str, Any]:
        """Return extra kwargs for psycopg2.connect."""
        extra: dict[str, Any] = {}
        if not self.model_extra:
            return extra
        for k, v in self.model_extra.items():
            # Only support top-level [zac.db] keys, no nesting, no containers, no None
            if not isinstance(v, (str, int, float, bool)):
                continue
            # Should not contain any of the model fields
            if k in self.__class__.model_fields:
                continue
            extra[k] = v
        return extra


class LogLevel(int, Enum):
    """Valid log levels."""

    NOTSET = logging.NOTSET
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

    def __str__(self) -> str:
        return self.name

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Custom core schema that serializes the log level as a string in JSON mode"""

        def validate_log_level(value: Any) -> LogLevel:
            if isinstance(value, cls):
                return value
            return cls(value)

        def serialize_log_level(value: LogLevel) -> str:
            return value.name

        return core_schema.no_info_after_validator_function(
            validate_log_level,
            core_schema.union_schema(
                [
                    core_schema.int_schema(),
                    core_schema.str_schema(),
                    core_schema.is_instance_schema(cls),
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                serialize_log_level, when_used="json"
            ),
        )

    @classmethod
    def _missing_(cls, value: object) -> LogLevel:
        """Handle arguments that are not valid log levels."""
        if isinstance(value, str):
            # Level as string
            if value.isnumeric():
                return cls(int(value))
            else:
                # Level as name, e.g. "DEBUG", "info", etc. (case-insensitive)
                try:
                    # Use logging module for conversion to handle aliases such as WARN and FATAL
                    return cls(logging._nameToLevel[value.upper()])  # pyright: ignore[reportPrivateUsage]
                except (ValueError, KeyError):
                    pass
        logger.error("Invalid log level '%s'. Using ERROR level.", value)
        return cls.ERROR


class LoggerFormat(str, Enum):
    JSON = "json"
    TEXT = "text"

    @classmethod
    def _missing(cls, value: object) -> LoggerFormat:
        """Handle missing logger formats."""
        try:
            return cls(str(value).lower())
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid logger format: {value}") from None


class LoggerConfigBase(ConfigBaseModel):
    enabled: bool = Field(
        default=True,
        description="Whether to enable this logger.",
    )
    format: LoggerFormat = Field(
        default=LoggerFormat.JSON,
        description="The format of the logger output.",
    )
    level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Log level for this logger. Uses global level if not set.",
    )


class ConsoleLoggerConfig(LoggerConfigBase):
    format: LoggerFormat = Field(
        default=LoggerFormat.TEXT,
        description="The format of the logger output.",
    )


class FileLoggerConfig(LoggerConfigBase):
    path: Path = Field(
        default=LOG_FILE_DEFAULT,
        description="Path to the log file.",
    )
    rotate: bool = Field(
        default=True,
        description="Whether to enable log rotation for the file logger.",
    )
    max_size_mb: int = Field(
        default=50,
        description="Maximum size of the log file in megabytes.",
    )
    max_logs: int = Field(
        default=5,
        description="Maximum number of log files to keep.",
    )

    def max_size_as_bytes(self) -> int:
        """Return the maximum size of the log file in bytes."""
        return self.max_size_mb * 1024 * 1024


class LoggingSettings(ConfigBaseModel):
    """Settings for logging configuration."""

    console: ConsoleLoggerConfig = Field(
        default_factory=ConsoleLoggerConfig,
        description="Settings for the console logger.",
    )
    file: FileLoggerConfig = Field(
        default_factory=FileLoggerConfig,
        description="Settings for the file logger.",
    )

    level: LogLevel = Field(
        default=LogLevel.INFO,
        description="The global log level to use for the logger. Used if sub-configs do not specify a log level.",
    )

    use_mp_handler: bool = Field(
        default=False,
        description=(
            "Activate multiprocessing_logging handler. Unclear if this is needed by default."
        ),
    )

    @model_validator(mode="after")
    def _set_log_levels_in_sub_configs(self) -> Self:
        if "level" not in self.console.model_fields_set:
            self.console.level = self.level
        if "level" not in self.file.model_fields_set:
            self.file.level = self.level
        return self


class ZacSettings(ConfigBaseModel):
    source_collector_dir: str
    host_modifier_dir: str
    health_file: Optional[Path] = None
    failsafe_file: Optional[Path] = None
    failsafe_ok_file: Optional[Path] = None
    failsafe_ok_file_strict: bool = True
    db: DBSettings = DBSettings()
    process: ProcessesSettings = ProcessesSettings()
    logging: LoggingSettings = LoggingSettings()

    # Deprecated options
    db_uri: str = Field(default="", deprecated=True)
    log_level: LogLevel = Field(
        # `logging` shadowed in class scope here
        LogLevel.INFO,
        description="The log level to use.",
        deprecated=True,
        exclude=True,
    )

    def _db_uri_to_db_settings(self, uri: str) -> None:
        """Parse a PostgreSQL libpq connection string into structured parameters.

        Args:
            uri: A PostgreSQL connection string in libpq format
                (e.g., "dbname='mydb' user='user' host='localhost'")

        Returns:
            PostgresConnectionParams containing the parsed connection parameters

        Example:
            >>> # NOTE: For illustration only, should not be called outside of validator.
            >>> self._db_uri_to_db_settings(
            ...     "dbname='mydb' user='user' host='localhost'"
            ... )
            >>> self.db.user
            'user'
            >>> self.db.password
            'password'
        """
        # Pattern matches key='value' or key=value pairs
        pattern = r"(\w+)\s*=\s*(?:'([^']*)'|(\d+))"
        matches = re.findall(pattern, uri)

        # Combine quoted and unquoted values, preferring quoted
        params = {match[0]: match[1] or match[2] for match in matches}

        self.db.user = params.pop("user", "")
        self.db.password = params.pop("password", "")
        self.db.dbname = params.pop("dbname", "zac")
        self.db.host = params.pop("host", "localhost")
        self.db.port = params.pop("port", 5432)
        self.db.connect_timeout = params.pop("connect_timeout", 5)

        if params:
            for key, value in params.items():
                # Set any remaining parameters as attributes on the DBSettings object
                setattr(self.db, key, value)

    # NOTE: remove this validator when db_uri is removed
    @model_validator(mode="after")
    def _require_db_or_db_uri(self) -> Self:
        """Compatibility layer for supporting legacy `db_uri` setting."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # ignore warnings in this block
            if self.db_uri:
                self._db_uri_to_db_settings(self.db_uri)
        return self

    # TODO: remove after log_level is removed
    @model_validator(mode="after")
    def _set_log_level_from_deprecated_log_level(self) -> Self:
        """Set the log level from the deprecated `log_level` field."""
        if (
            "log_level" in self.model_fields_set
            and "level" not in self.logging.model_fields_set
        ):
            # If log_level is set, but not in logging sub-config, set it there
            self.logging.level = LogLevel(self.log_level)
            logger.warning(
                "The `log_level` field is deprecated. Use `zac.logging.level` instead."
            )
        return self

    @field_validator("health_file", "failsafe_file", "failsafe_ok_file", mode="after")
    @classmethod
    def _validate_file_path(
        cls, v: Optional[Path], info: ValidationInfo
    ) -> Optional[Path]:
        if v is None:
            return v
        if v.exists() and v.is_dir():
            raise ValueError(f"'{info.field_name}' cannot be a directory")
        if not v.exists():
            utils.make_parent_dirs(v)
        return v


class FailureStrategy(str, Enum):
    """Strategies for handling collector failures."""

    EXIT = "exit"
    DISABLE = "disable"
    BACKOFF = "backoff"
    NONE = "none"

    def supports_error_tolerance(self) -> bool:
        """Whether the strategy supports error tolerance."""
        return self in {FailureStrategy.EXIT, FailureStrategy.DISABLE}


class SourceCollectorSettings(ConfigBaseModel):
    module_name: str
    update_interval: int = Field(..., ge=0)
    error_tolerance: int = Field(
        default=0,
        description="Number of errors to allow within the last `error_duration` seconds before marking the collector as failing.",
        ge=0,
    )
    error_duration: int = Field(
        default=0,
        description=(
            "The duration in seconds that errors are stored."
            "If `error_tolerance` errors occur in this period, the collector is marked as failing."
            "If `error_tolerance`is set, but this is not, it is set to `round(error_tolerance * update_interval + (update_interval*0.9))`."
        ),
        ge=0,
    )
    exit_on_error: bool = Field(
        default=False,
        description="Exit ZAC if the collector failure tolerance is exceeded. Collector is disabled otherwise.",
    )
    disable_duration: int = Field(
        default=0,
        description="Duration to disable the collector for if the error tolerance is exceeded.",
    )
    backoff_factor: float = Field(
        default=1.5,
        description="Factor to multiply the update interval by when the collector is disabled.",
        ge=1.0,
    )
    max_backoff: float = Field(
        default=3600,
        description="Maximum backoff duration in seconds.",
        ge=0,
    )

    model_config = ConfigDict(
        # Validators cause infinte recursion if assignment validation is enabled.
        # TODO: fix
        validate_assignment=False,
        extra="allow",
    )

    @property
    def failure_strategy(self) -> FailureStrategy:
        # Supercedes disable_duration-based strategies
        if self.exit_on_error:
            return FailureStrategy.EXIT
        if self.disable_duration > 0:
            return FailureStrategy.DISABLE
        if self.disable_duration == 0:
            return FailureStrategy.BACKOFF
        # Never disable if < 0
        return FailureStrategy.NONE

    def _validate_error_duration_is_greater(self) -> None:
        """Ensure error tolerance and treshold is set correctly."""
        # If no tolerance, we don't need to be concerned with how long errors
        # are kept on record, because a single error will disable the collector.
        if self.error_tolerance <= 0:
            # hack to ensure RollingErrorCounter.count() doesn't discard the error
            # before it is counted
            self.error_duration = 9999
            return

        # Set default error duration if not set
        if self.error_tolerance > 0 and not self.error_duration:
            # Set the error duration to tolerance * update_interval + 90% of update_interval
            # so that it's possible to hit the error tolerance within the duration if all
            # errors happen in succession.
            self.error_duration = round(
                self.error_tolerance * self.update_interval
                + (self.update_interval * 0.9)
            )

        # Ensure the error duration is greater than the product of the error tolerance and update interval
        if (
            product := self.error_tolerance * self.update_interval
        ) > self.error_duration:
            raise ValueError(
                f"Invalid value for error_duration ({self.error_duration}). "
                f"It should be greater than {product}: error_tolerance ({self.error_tolerance}) * update_interval ({self.update_interval})"
            )
        return

    def _validate_backoff_settings(self) -> None:
        """Ensure backoff settings are valid."""
        if not self.failure_strategy == FailureStrategy.BACKOFF:
            return

        # Update interval of 0 cannot be used with backoff strategy
        if self.update_interval == 0:
            logger.debug(
                "Update interval for collector '%s' is 0, but exponential backoff strategy is set due to `disable_duration = 0`. "
                "Setting `disable_duration = -1` so no failure strategy is applied.",
                self.module_name,
            )
            self.disable_duration = -1
            assert self.failure_strategy == FailureStrategy.NONE

        # Ensure any errors cause backoff to be triggered
        if self.error_tolerance != 0:
            self.error_tolerance = 0
            logger.debug(
                "Setting error_tolerance to 0 for collector '%s' due to backoff strategy",
                self.module_name,
            )

        if self.max_backoff < self.update_interval:
            raise ValueError(
                f"Invalid value for max_backoff ({self.max_backoff}). "
                f"It should be greater than or equal to update_interval ({self.update_interval})"
            )

    @model_validator(mode="after")
    def _do_validate(self) -> Self:
        # Guarantee validator order by having a single validator that calls
        # other validators in the desired order.
        # TODO: refactor methods. Too much logic and mutation in each validator.
        self._validate_error_duration_is_greater()
        self._validate_backoff_settings()
        return self

    def extra_kwargs(self) -> dict[str, Any]:
        """Return all extra keys as kwargs to pass to a source collector's `collect()` function."""
        # Just return BaseModel.model_extra as-is for now
        return self.model_extra or {}


class Settings(ConfigBaseModel):
    zac: ZacSettings
    zabbix: ZabbixSettings
    source_collectors: dict[str, SourceCollectorSettings]

    config_path: Optional[Path] = Field(
        default=None, description="Path the config was loaded from.", exclude=True
    )


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

        log = logger.bind(hostname=self.hostname)

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
