from __future__ import annotations

import logging
import logging.handlers
import sys
from dataclasses import dataclass

import structlog
from structlog.dev import Column

from zabbix_auto_config.dirs import ensure_directory
from zabbix_auto_config.models import FileLoggerConfig
from zabbix_auto_config.models import LoggerConfigBase
from zabbix_auto_config.models import LoggerFormat
from zabbix_auto_config.models import Settings


@dataclass
class ProcessNameFormatter:
    """Formatter for process name in the log output."""

    style: str
    reset_style: str

    def __call__(self, key: str, value: object) -> str:
        return f"[{self.style}{value}{self.reset_style}]"


shared_processors = [
    structlog.stdlib.filter_by_level,
    structlog.stdlib.add_log_level,
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
    structlog.processors.CallsiteParameterAdder(
        parameters=[structlog.processors.CallsiteParameter.PROCESS_NAME]
    ),
    structlog.processors.UnicodeDecoder(),
    structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
]
"""Shared processors for structlog that are used in both console and file logging."""


def get_console_renderer() -> structlog.dev.ConsoleRenderer:
    """Create a console renderer that renders the process name before the event."""
    renderer = structlog.dev.ConsoleRenderer(colors=True)

    # HACK: Insert the process name column into the renderer's columns.
    # The "proper" way would be to create _all_ columns manually,
    # which is a lot of boilerplate.
    renderer._columns.insert(
        2,
        Column(
            "process_name",
            ProcessNameFormatter(
                style=renderer._styles.timestamp,
                reset_style=renderer._styles.reset,
            ),
        ),
    )
    return renderer


def get_file_handler(config: FileLoggerConfig) -> logging.FileHandler:
    """Get the correct type of file handler based on the configuration."""
    log_path = config.path
    ensure_directory(log_path.parent)  # ensure parent directories exist
    if config.rotate:
        handler = logging.handlers.RotatingFileHandler(
            config.path,
            maxBytes=config.max_size_as_bytes(),
            backupCount=config.max_logs,
        )
    else:
        handler = logging.FileHandler(config.path)
    return handler


def get_formatter(config: LoggerConfigBase) -> structlog.stdlib.ProcessorFormatter:
    """Get a structlog formatter based on the logger configuration."""
    if config.format == LoggerFormat.TEXT:
        return structlog.stdlib.ProcessorFormatter(
            processor=get_console_renderer(),
            foreign_pre_chain=shared_processors,
        )
    else:
        return structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=shared_processors,
        )


def configure_logging(config: Settings) -> None:
    # Create the root logger and clear its default handlers
    root_logger = logging.getLogger()
    root_logger.setLevel(config.zac.logging.level)
    root_logger.handlers = []

    if config.zac.logging.use_mp_handler:
        import multiprocessing_logging

        multiprocessing_logging.install_mp_handler()

    structlog.configure(
        processors=shared_processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    # Set up formatters and handlers
    # 1. File handler
    if config.zac.logging.file.enabled:
        file_handler = get_file_handler(config.zac.logging.file)
        file_handler.setFormatter(get_formatter(config.zac.logging.file))
        file_handler.setLevel(config.zac.logging.file.level)
        root_logger.addHandler(file_handler)
    # 2. Console handler
    if config.zac.logging.console.enabled:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(get_formatter(config.zac.logging.console))
        console_handler.setLevel(config.zac.logging.level)
        root_logger.addHandler(console_handler)

    # Set level of other loggers that we want to capture
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.ERROR)

    # Show which file is being logged to (if any)
    if config.zac.logging.file.enabled:
        structlog.get_logger().info(
            "Logging to file",
            file=str(config.zac.logging.file.path),
            log_level=str(config.zac.logging.file.level),
        )
