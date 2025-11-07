"""Directories and files used by the application."""

from __future__ import annotations

from pathlib import Path

import structlog
from platformdirs import PlatformDirs

logger = structlog.stdlib.get_logger(__name__)

pdirs = PlatformDirs("zabbix-auto-config", "unioslo")

CONFIG_DIR = pdirs.user_config_path
CONFIG_FILENAME = "config.toml"
CONFIG_FILE_DEFAULT = CONFIG_DIR / "config.toml"

LOG_DIR = pdirs.user_log_path
LOG_FILENAME = "app.log"
LOG_FILE_DEFAULT = LOG_DIR / "app.log"


def ensure_directory(path: Path) -> None:
    """Create a directory if it does not exist."""
    log = logger.bind(file=path)
    if path.exists():
        log.debug("Directory already exists")
        return
    try:
        path.mkdir(parents=True, exist_ok=True)
        log.info("Created directory")
    except Exception as e:
        log.exception("Failed to create directory")
        raise RuntimeError(f"Failed to create directory {path}: {e}") from e
