"""Directories and files used by the application."""

from __future__ import annotations

from platformdirs import PlatformDirs

pdirs = PlatformDirs("zabbix-auto-config", "unioslo")

CONFIG_DIR = pdirs.user_config_path
CONFIG_FILENAME = "config.toml"
CONFIG_FILE_DEFAULT = CONFIG_DIR / "config.toml"

LOG_DIR = pdirs.user_log_path
LOG_FILENAME = "app.log"
LOG_FILE_DEFAULT = LOG_DIR / "app.log"
