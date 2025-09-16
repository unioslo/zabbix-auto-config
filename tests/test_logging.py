from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

import structlog
import zabbix_auto_config.log
from inline_snapshot import snapshot
from structlog.types import EventDict
from zabbix_auto_config.models import Settings


@contextmanager
def capture_logs_with_processors() -> Iterator[list[EventDict]]:
    """Re-implementation of structlog.testing.capture_logs that keeps existing processors."""
    processors = structlog.get_config()["processors"]
    old_processors = processors.copy()
    processors = [
        p
        for p in processors
        if not isinstance(
            p, (structlog.processors.JSONRenderer, structlog.dev.ConsoleRenderer)
        )
    ]
    cap = structlog.testing.LogCapture()
    processors.insert(-1, cap)  # before wrap_for_formatter
    try:
        structlog.configure(processors=processors)
        yield cap.entries
    finally:
        processors[:] = old_processors


def test_set_serialization(config: Settings) -> None:
    zabbix_auto_config.log.configure_logging(config)
    logger = structlog.stdlib.get_logger("test_logger")
    with capture_logs_with_processors() as log:
        logger.info("Test message", myset={"a", "b", "c"})
        assert len(log) == 1
        assert isinstance(log[0]["myset"], list)  # from set to list
        assert set(log[0]["myset"]) == {"a", "b", "c"}


def test_logging_config_file_disabled(config: Settings) -> None:
    config.zac.logging.file.enabled = False

    # Try configuring the logger with file logging disabled
    zabbix_auto_config.log.configure_logging(config)

    logger = structlog.stdlib.get_logger("test_logger")

    # Check the number of handlers on the root logger
    parent = logger.new().parent
    assert parent.name == "root"
    assert len(parent.handlers) == snapshot(1)
    assert isinstance(parent.handlers[0], logging.StreamHandler)

    with capture_logs_with_processors() as log:
        logger.info("Test message")
        assert len(log) == 1


def test_logging_config_console_disabled(config: Settings) -> None:
    config.zac.logging.console.enabled = False

    # Try configuring the logger with console logging disabled
    zabbix_auto_config.log.configure_logging(config)

    logger = structlog.stdlib.get_logger("test_logger")

    # Check the number of handlers on the root logger
    parent = logger.new().parent
    assert parent.name == "root"
    assert len(parent.handlers) == snapshot(1)
    assert isinstance(parent.handlers[0], logging.FileHandler)  # should be rotating

    with capture_logs_with_processors() as log:
        logger.info("Test message")
        assert len(log) == 1


def test_logging_config_both_disabled(config: Settings) -> None:
    config.zac.logging.console.enabled = False
    config.zac.logging.file.enabled = False

    # Try configuring the logger with both console and file logging disabled
    zabbix_auto_config.log.configure_logging(config)

    logger = structlog.stdlib.get_logger("test_logger")

    # Check the number of handlers on the root logger
    parent = logger.new().parent
    assert parent.name == "root"
    assert len(parent.handlers) == snapshot(0)

    # No handlers, but we still process the logs
    with capture_logs_with_processors() as log:
        logger.info("Test message")
        assert len(log) == 1


def test_log_exceptions_before_processing(config: Settings) -> None:
    zabbix_auto_config.log.configure_logging(config)
    logger = structlog.stdlib.get_logger("test_logger")

    with capture_logs_with_processors() as log_output:
        try:
            1 / 0  # noqa: B018  # pyright: ignore[reportUnusedExpression]
        except ZeroDivisionError:
            logger.exception("An error occurred")
        assert len(log_output) == 1
        del log_output[0]["timestamp"]

        # Before processing, we should still have exc_info=True
        assert log_output[0] == snapshot(
            {
                "exc_info": True,
                "event": "An error occurred",
                "level": "error",
                "process_name": "MainProcess",
                "log_level": "error",
            }
        )


def test_log_exceptions_after_processing(config: Settings) -> None:
    zabbix_auto_config.log.configure_logging(config)
    logger = structlog.stdlib.get_logger("test_logger")

    try:
        1 / 0  # noqa: B018  # pyright: ignore[reportUnusedExpression]
    except ZeroDivisionError:
        logger.exception("An error occurred")

    logfile = config.zac.logging.file.path.read_text()
    # After processing, `exc_info` should be replaced with `exception`
    assert "exc_info" not in logfile
    assert '"exception": [' in logfile
    assert "division by zero" in logfile


def test_log_exceptions_after_processing_external_logger(config: Settings) -> None:
    zabbix_auto_config.log.configure_logging(config)
    stdlib_logger = logging.getLogger("httpx")

    try:
        1 / 0  # noqa: B018  # pyright: ignore[reportUnusedExpression]
    except ZeroDivisionError:
        stdlib_logger.exception("An error occurred")

    logfile = config.zac.logging.file.path.read_text()
    assert "exc_info" not in logfile
    assert '"exception": [' in logfile  # Formatted exception
    assert "division by zero" in logfile
