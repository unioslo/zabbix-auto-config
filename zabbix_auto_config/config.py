"""ZAC configuration module."""
# TODO: move `models.Settings` and its dependencies to this module.

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import structlog

# Use standard library for Python 3.11+, fallback to tomli for older versions
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from zabbix_auto_config import models
from zabbix_auto_config.dirs import CONFIG_FILE_DEFAULT
from zabbix_auto_config.dirs import CONFIG_FILENAME
from zabbix_auto_config.exceptions import ConfigFileNotFoundError
from zabbix_auto_config.exceptions import ConfigValidationError

logger = structlog.stdlib.get_logger(__name__)


CONFIG_PATHS = [
    Path(".") / CONFIG_FILENAME,
    CONFIG_FILE_DEFAULT,
]


def get_config(path: Optional[Path] = None) -> models.Settings:
    """Load the ZAC configuration from the first available configuration file."""
    # We have a specific path, load it
    if path:
        return load_config(path)

    # Fallback on finding a config file
    for path in CONFIG_PATHS:
        try:
            return load_config(path)
        except ConfigFileNotFoundError as e:
            logger.debug(e)
        except ConfigValidationError as e:
            logger.error(e)
    raise FileNotFoundError(f"No valid configuration file found in {CONFIG_PATHS}")


def load_config(config_file: Path) -> models.Settings:
    """Load a ZAC configuration file from the given location."""
    try:
        return _load_config(config_file)
    except FileNotFoundError as e:
        raise ConfigFileNotFoundError(
            f"Configuration file {config_file} not found."
        ) from e
    except Exception as e:  # catch-all for unexpected errors
        raise ConfigValidationError(
            f"Error loading configuration from {config_file}: {e}"
        ) from e


def _load_config(config_file: Path) -> models.Settings:
    """Load a ZAC configuration file from the given location."""
    with open(config_file, "rb") as f:
        config_dict = tomllib.load(f)
    config = models.Settings(**config_dict)
    config.config_path = config_file
    return config
