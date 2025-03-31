"""ZAC configuration module."""
# TODO: move `models.Settings` and its dependencies to this module.

from __future__ import annotations

import logging
from pathlib import Path

import tomli

from zabbix_auto_config import models
from zabbix_auto_config.dirs import CONFIG_FILE_DEFAULT
from zabbix_auto_config.dirs import CONFIG_FILENAME

logger = logging.getLogger(__name__)


CONFIG_PATHS = [
    Path(".") / CONFIG_FILENAME,
    CONFIG_FILE_DEFAULT,
]


def get_config() -> models.Settings:
    """Load the ZAC configuration from the first available configuration file."""
    for path in CONFIG_PATHS:
        try:
            return _load_config(path)
        except FileNotFoundError:
            logger.debug("No configuration file found in %s", path)
        except Exception as e:  # catch-all for unexpected errors
            logger.error("Error loading configuration from %s: %s", path, e)
    raise FileNotFoundError(f"No valid configuration file found in {CONFIG_PATHS}")


def _load_config(config_file: Path) -> models.Settings:
    """Load a ZAC configuration file from the given location."""
    with open(config_file) as f:
        content = f.read()
    config_dict = tomli.loads(content)
    config = models.Settings(**config_dict)
    return config
