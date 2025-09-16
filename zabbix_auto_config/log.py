from __future__ import annotations

import logging
import logging.config
import logging.handlers
from typing import Any

import structlog
from structlog.typing import EventDict

from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.models import FileLoggerConfig
from zabbix_auto_config.models import LoggerConfigBase
from zabbix_auto_config.models import Settings


def _serialize_sets(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Convert sets to lists for JSON serialization."""
    for key, value in event_dict.items():
        if isinstance(value, set):
            event_dict[key] = list(value)
    return event_dict


timestamper = structlog.processors.TimeStamper(fmt="iso")

pre_chain = [
    structlog.stdlib.add_log_level,
    timestamper,
    structlog.stdlib.ExtraAdder(),
    _serialize_sets,
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
        raise ZACException(
            str(e),
            path=str(config.path),
            show_traceback=False,
        ) from e
    return handler


def get_formatter_name(config: LoggerConfigBase) -> str:
    """Get the formatter name based on the configuration."""
    if config.format == "json":
        return "file"
    return "console"


def get_file_handler_config(config: FileLoggerConfig) -> dict[str, str | int]:
    """Get a dict config for a file handler based on the configuration."""

    logging_class = (
        "logging.handlers.RotatingFileHandler"
        if config.rotate
        else "logging.FileHandler"
    )
    handler_config: dict[str, str | int] = {
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

    config_dict: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.dev.ConsoleRenderer(colors=True),
                ],
                "foreign_pre_chain": pre_chain,
            },
            "file": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.processors.dict_tracebacks,
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer(),
                ],
                "foreign_pre_chain": pre_chain,
            },
        },
        "handlers": {
            "default": {
                "level": config.zac.logging.console.level.name,
                "class": "logging.StreamHandler",
                "formatter": get_formatter_name(config.zac.logging.console),
            },
            "file": get_file_handler_config(config.zac.logging.file),
        },
        "loggers": {
            "": {
                "handlers": ["default", "file"],
                "level": "DEBUG",  # handlers filter by their own level
                "propagate": True,
            },
        },
    }
    # NOTE: this seems hacky?
    if not config.zac.logging.file.enabled:
        del config_dict["handlers"]["file"]
        config_dict["loggers"][""]["handlers"].remove("file")
    if not config.zac.logging.console.enabled:
        del config_dict["handlers"]["default"]
        config_dict["loggers"][""]["handlers"].remove("default")

    logging.config.dictConfig(config_dict)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.CallsiteParameterAdder(
                parameters=[structlog.processors.CallsiteParameter.PROCESS_NAME]
            ),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.UnicodeDecoder(),
            _serialize_sets,
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
