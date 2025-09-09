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

shared_processors = [
    structlog.stdlib.add_log_level,
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.CallsiteParameterAdder(
        parameters=[structlog.processors.CallsiteParameter.PROCESS_NAME]
    ),
    structlog.processors.UnicodeDecoder(),
]
"""Shared processors for structlog that are used in both console and file logging."""


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
                    "process_name",
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
    def create(cls) -> ZacConsoleRenderer:
        """Create a new instance of the ZacConsoleRenderer."""
        instance = cls(colors=True, sort_keys=False)
        instance.add_process_name_formatter()
        return instance


def get_file_handler(config: FileLoggerConfig) -> logging.FileHandler:
    """Get the correct type of file handler based on the configuration."""
    log_path = config.path
    ensure_directory(log_path.parent)  # ensure parent directories exist
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
        structlog.stdlib.get_logger().error(
            "Failed to create file handler", error=str(e), file=config.path
        )
        raise
    return handler


def get_formatter(config: LoggerConfigBase) -> structlog.stdlib.ProcessorFormatter:
    """Get a structlog formatter based on the logger configuration."""

    if config.format == LoggerFormat.TEXT:
        return structlog.stdlib.ProcessorFormatter(
            processor=ZacConsoleRenderer.create(),
            foreign_pre_chain=shared_processors,
        )
    else:
        return structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.add_logger_name,
                structlog.processors.dict_tracebacks,
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
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
        processors=[structlog.stdlib.filter_by_level]
        + shared_processors
        + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
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
    # TODO: Test capture of these logs!
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Show which file is being logged to (if any)
    if config.zac.logging.file.enabled:
        structlog.get_logger().info(
            "Logging to file",
            file=str(config.zac.logging.file.path),
            log_level=str(config.zac.logging.file.level),
        )
