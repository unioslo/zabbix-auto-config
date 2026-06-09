from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager

import pytest
import structlog
import zabbix_auto_config.log
from inline_snapshot import snapshot
from structlog.types import EventDict
from zabbix_auto_config.config import Settings
from zabbix_auto_config.log import REDACTED_STR


@contextmanager
def capture_logs_with_processors() -> Generator[list[EventDict], None, None]:
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


@pytest.fixture(autouse=True)
def configure_logging_fixture(config: Settings) -> Generator[None, None, None]:
    """Configure logging using the test config for all tests in this module."""
    zabbix_auto_config.log.configure_logging(config)
    yield


def test_set_serialization() -> None:
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


def test_log_exceptions_before_processing() -> None:
    logger = structlog.stdlib.get_logger("test_logger")

    with capture_logs_with_processors() as log_output:
        try:
            1 / 0  # noqa: B018  # pyright: ignore[reportUnusedExpression]
        except ZeroDivisionError:
            logger.exception("An error occurred")
        assert len(log_output) == 1
        log_output[0].pop("timestamp", None)  # remove timestamp if present

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
    stdlib_logger = logging.getLogger("httpx")

    try:
        1 / 0  # noqa: B018  # pyright: ignore[reportUnusedExpression]
    except ZeroDivisionError:
        stdlib_logger.exception("An error occurred")

    logfile = config.zac.logging.file.path.read_text()
    assert "exc_info" not in logfile
    assert '"exception": [' in logfile  # Formatted exception
    assert "division by zero" in logfile


def test_log_redaction_simple() -> None:
    """Test that sensitive information is redacted in logs (no recursion needed)."""
    logger = structlog.stdlib.get_logger("test_logger")

    with capture_logs_with_processors() as logs:
        logger.info("Test message", password="secret", token="12345", auth="token")
        assert len(logs) == 1
        assert logs[0]["password"] == REDACTED_STR
        assert logs[0]["token"] == REDACTED_STR
        assert logs[0]["auth"] == REDACTED_STR


def test_log_redaction_contains() -> None:
    """Test redaction where keys _contain_ the keywords."""
    logger = structlog.stdlib.get_logger("test_logger")

    with capture_logs_with_processors() as logs:
        logger.info(
            "Test message",
            user_password="secret",
            api_token="12345",
            admin_auth="token",
        )
        assert len(logs) == 1
        assert logs[0]["user_password"] == REDACTED_STR
        assert logs[0]["api_token"] == REDACTED_STR
        assert logs[0]["admin_auth"] == REDACTED_STR


def test_log_redaction_case_insensitive() -> None:
    """Test case insensitivity in redaction."""
    logger = structlog.stdlib.get_logger("test_logger")

    with capture_logs_with_processors() as logs:
        logger.info(
            "Test message",
            # Exact
            Password="secret",
            TokeN="TokeN_12345",
            AUTH="AUTH_TOKEN",
            # Contains
            user_Password="secret",
            API_TokeN="12345",
            admin_AUTH="token",
        )
        assert len(logs) == 1
        assert logs[0]["user_Password"] == REDACTED_STR
        assert logs[0]["API_TokeN"] == REDACTED_STR
        assert logs[0]["admin_AUTH"] == REDACTED_STR
        assert logs[0]["Password"] == REDACTED_STR
        assert logs[0]["TokeN"] == REDACTED_STR
        assert logs[0]["AUTH"] == REDACTED_STR


def test_log_redaction_recursion() -> None:
    """Test that sensitive information is redacted in logs (with recursion)."""
    logger = structlog.stdlib.get_logger("test_logger")

    with capture_logs_with_processors() as logs:
        logger.info(
            "Test message",
            request_body={
                "username": "user",
                "password": "secret",
                "auth": "12345",
            },
        )
        assert len(logs) == 1
        assert logs[0]["request_body"]["username"] == "user"
        assert logs[0]["request_body"]["password"] == REDACTED_STR
        assert logs[0]["request_body"]["auth"] == REDACTED_STR


def test_log_redaction_recursion_advanced_types() -> None:
    """Test redaction with advanced types and nested structures."""
    logger = structlog.stdlib.get_logger("test_logger")

    with capture_logs_with_processors() as logs:
        logger.info(
            "Test message",
            request_body={
                "nested": {
                    "token": "abcdef",
                    "list_of_dicts": [
                        {"auth_key": "key123"},
                        {"not_sensitive": "value"},
                    ],
                },
            },
            auth_list=[["password", "secret"], ["auth", "12345"]],
        )
        assert len(logs) == 1
        assert logs[0]["request_body"]["nested"]["token"] == REDACTED_STR
        assert (
            logs[0]["request_body"]["nested"]["list_of_dicts"][0]["auth_key"]
            == REDACTED_STR
        )
        assert (
            logs[0]["request_body"]["nested"]["list_of_dicts"][1]["not_sensitive"]
            == "value"  # not redacted
        )

        # Simple values in lists should not be redacted
        assert logs[0]["auth_list"] == [["password", "secret"], ["auth", "12345"]]
