from __future__ import annotations

import logging
import logging.config
import logging.handlers
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Union

import structlog
from structlog.dev import Column
from structlog.typing import EventDict

from zabbix_auto_config.config import ConsoleLoggerConfig
from zabbix_auto_config.config import FileLoggerConfig
from zabbix_auto_config.config import LoggerConfigBase
from zabbix_auto_config.config import Settings
from zabbix_auto_config.dirs import ensure_directory
from zabbix_auto_config.exceptions import ZACException

HandlerDict = MutableMapping[str, Union[str, int]]


@dataclass
class ProcessNameFormatter:
    """Formatter for process name in the log output."""

    style: str
    reset_style: str

    def __call__(self, key: str, value: object) -> str:
        return f"[{self.style}{value}{self.reset_style}]"


class ZacConsoleRenderer(structlog.dev.ConsoleRenderer):
    def add_process_name_formatter(self) -> None:
        """Add a process name formatter to the console renderer (in-place)."""

        try:
            # HACK: Insert the process name column into the renderer's columns.
            # The "proper" way would be to create _all_ columns manually,
            # which is a lot of boilerplate.
            self._columns.insert(
                2,
                Column(
                    # Use the same parameter as in pre_chain as key
                    structlog.processors.CallsiteParameter.PROCESS_NAME.value,
                    ProcessNameFormatter(
                        style=self._styles.timestamp,
                        reset_style=self._styles.reset,
                    ),
                ),
            )
        except Exception as e:
            structlog.stdlib.get_logger().error(
                "Failed to initialize process name formatter", error=str(e)
            )

    @classmethod
    def create(cls, config: ConsoleLoggerConfig) -> ZacConsoleRenderer:
        """Create a new instance of the ZacConsoleRenderer."""
        if config.exception_formatter == "rich":
            exc_fmt = structlog.dev.rich_traceback
        else:
            exc_fmt = structlog.dev.plain_traceback
        instance = cls(
            colors=True,
            sort_keys=False,
            exception_formatter=exc_fmt,
        )
        instance.add_process_name_formatter()
        return instance


def _serialize_types(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Convert types without native JSON representation to a serializable format.

    Unknown types are converted to their their repr() string, which is not always ideal."""
    for key, value in event_dict.items():
        if isinstance(value, set):
            event_dict[key] = list(value)
        elif isinstance(value, Path):
            event_dict[key] = str(value)
    return event_dict


SECRETS_KEYS = {"password", "token", "auth"}
"""Set of keywords in which values should be redacted in logs if keys contain them.

I.e. "my_password", "auth_token" would be redacted, but "my_pass" would not.
"""

REDACTED_STR = "<REDACTED>"


def _redact_secrets(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Recursively redact sensitive information in the event dictionary."""
    for key, value in event_dict.items():
        event_dict[key] = _do_redact_secrets(key, value)
    return event_dict


def _do_redact_secrets(key: str, value: Any) -> Any:
    """Helper function to recursively redact secrets in a value."""
    if isinstance(value, dict):
        return {k: _do_redact_secrets(k, v) for k, v in value.items()}
    # Do not redact simple list values (["password", "auth"], etc.)
    # Pass empty key, so that simple iterate values are not redacted.
    elif isinstance(value, list):
        return [_do_redact_secrets("", v) for v in value]
    elif isinstance(value, set):
        return {_do_redact_secrets("", v) for v in value}
    elif isinstance(value, tuple):
        return tuple(_do_redact_secrets("", v) for v in value)
    else:
        if key and any(k in key.lower() for k in SECRETS_KEYS):
            return REDACTED_STR
        else:
            return value


timestamper = structlog.processors.TimeStamper(fmt="iso")

shared_processors = [
    structlog.stdlib.add_log_level,
    structlog.processors.CallsiteParameterAdder(
        parameters=[structlog.processors.CallsiteParameter.PROCESS_NAME]
    ),
]
transformers = [_serialize_types, _redact_secrets]

pre_chain = [
    *shared_processors,
    structlog.stdlib.ExtraAdder(),
    *transformers,
]
"""Pre chain for non-structlog loggers (e.g. standard library)."""


def get_file_handler(config: FileLoggerConfig) -> logging.FileHandler:
    """Get the correct type of file handler based on the configuration."""
    try:
        if config.rotate:
            handler = logging.handlers.RotatingFileHandler(
                config.path,
                maxBytes=config.max_size_as_bytes(),
                backupCount=config.max_logs,
            )
        else:
            handler = logging.FileHandler(config.path)
    except OSError as e:
        # Raise error with context which is caught by handler
        raise ZACException(str(e)) from e
    return handler


def get_formatter_name(config: LoggerConfigBase) -> str:
    """Get the formatter name based on the configuration."""
    if config.format == "json":
        return "file"
    return "console"


def get_console_handler_config(config: ConsoleLoggerConfig) -> HandlerDict:
    """Get a dict config for a console handler based on the configuration."""
    return {
        "level": config.level.name,
        "class": "logging.StreamHandler",
        "formatter": get_formatter_name(config),
    }


def get_file_handler_config(config: FileLoggerConfig) -> HandlerDict:
    """Get a dict config for a file handler based on the configuration."""

    logging_class = (
        "logging.handlers.RotatingFileHandler"
        if config.rotate
        else "logging.FileHandler"
    )
    handler_config: HandlerDict = {
        "class": logging_class,
        "filename": str(config.path),
        "encoding": "utf8",
        "level": config.level.name,
        "formatter": get_formatter_name(config),
    }
    if config.rotate:
        handler_config.update(
            {
                "maxBytes": config.max_size_as_bytes(),
                "backupCount": config.max_logs,
            }
        )
    return handler_config


def configure_logging(config: Settings) -> None:
    # Create the root logger and clear its default handlers
    root_logger = logging.getLogger()
    root_logger.setLevel(config.zac.logging.level)

    # Build handlers conditionally based on config
    handlers: dict[str, HandlerDict] = {}
    if config.zac.logging.console.enabled:
        handlers["default"] = get_console_handler_config(config.zac.logging.console)
    if config.zac.logging.file.enabled:
        handlers["file"] = get_file_handler_config(config.zac.logging.file)

    config_dict: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    ZacConsoleRenderer.create(config.zac.logging.console),
                ],
                "foreign_pre_chain": pre_chain,
            },
            "file": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    timestamper,
                    structlog.processors.dict_tracebacks,
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer(),
                ],
                "foreign_pre_chain": pre_chain,
            },
        },
        "handlers": handlers,
        "loggers": {
            "": {
                "handlers": list(handlers),
                "level": "DEBUG",  # handlers filter by their own level
                "propagate": True,
            },
        },
    }

    # Create log directory _before_ instantiating logger
    if config.zac.logging.file.enabled:
        ensure_directory(config.zac.logging.file.path.parent)

    logging.config.dictConfig(config_dict)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.UnicodeDecoder(),
            *transformers,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Show which file is being logged to (if any)
    if config.zac.logging.file.enabled:
        structlog.get_logger().debug(
            "Logging to file",
            file=str(config.zac.logging.file.path),
            level=config.zac.logging.file.level,
        )
