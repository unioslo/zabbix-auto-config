from __future__ import annotations

import logging
import sys

import multiprocessing_logging
import structlog

from zabbix_auto_config.models import Settings

if sys.stderr.isatty():
    pass


class CustomConsoleRenderer:
    """Custom renderer that puts process_name in brackets."""

    def __init__(self, colors=True):
        # Use the default ConsoleRenderer for colorization
        self._console_renderer = structlog.dev.ConsoleRenderer(colors=colors)

    def __call__(self, logger, name, event_dict):
        # Extract process_name if it exists
        process_name = event_dict.pop("process_name", None)

        # Build the formatted message parts
        parts = []

        # Timestamp
        if "timestamp" in event_dict:
            parts.append(event_dict.pop("timestamp"))

        # Process name in brackets
        if process_name:
            parts.append(f"[{process_name}]")

        # Log level
        if "level" in event_dict:
            level = event_dict.pop("level")
            parts.append(f"[{level:<8}]")  # Left-align with padding

        # Event message
        if "event" in event_dict:
            parts.append(event_dict.pop("event"))

        # Join the parts
        prefix = " ".join(parts)

        # If there are remaining key-value pairs, render them
        if event_dict:
            # Put the remaining dict back with just the extra fields
            remaining_dict = {"event": "", **event_dict}
            _, _, rendered_dict = self._console_renderer(logger, name, remaining_dict)
            # Remove the empty event from the rendered output
            rendered_dict = rendered_dict.replace('event="" ', "").replace(
                'event=""', ""
            )
            if rendered_dict.strip():
                return f"{prefix} {rendered_dict.strip()}"

        return prefix


def configure_logging(config: Settings) -> None:
    multiprocessing_logging.install_mp_handler()

    # Create the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(config.zac.logging.level)

    # Remove any existing handlers
    root_logger.handlers = []

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

    # Configure structlog to output JSON to file and formatted text to stdout
    structlog.configure(
        processors=shared_processors,
        # wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    # Set up formatters and handlers
    # 1. JSON file handler
    if config.zac.logging.file:
        file_handler = logging.FileHandler("app.log")
        file_handler.setLevel(logging.INFO)
        file_formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=shared_processors,
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # 2. Console handler for human-readable output
    # Human-readable formatter for console
    if config.zac.logging.stderr:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        console_formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.dev.ConsoleRenderer(colors=True),
            foreign_pre_chain=shared_processors,
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # Set level of loggers
    logging.getLogger().setLevel(config.zac.log_level)
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.ERROR)
