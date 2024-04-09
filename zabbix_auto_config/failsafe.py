from __future__ import annotations

import logging
from typing import List

from zabbix_auto_config import models
from zabbix_auto_config.models import ZacSettings


def check_failsafe_ok(config: ZacSettings) -> bool:
    """Checks the failsafe OK file and returns True if application should proceed."""
    # Check for presence of file
    if not config.failsafe_ok_file:
        return False
    if not config.failsafe_ok_file.exists():
        logging.info(
            "Failsafe OK file %s does not exist. Create it to approve changes.",
            config.failsafe_ok_file,
        )
        return False
    # File exists, attempt to delete it
    try:
        config.failsafe_ok_file.unlink()
    except OSError as e:
        logging.error("Unable to delete failsafe OK file: %s", e)
        if config.failsafe_ok_file_strict:
            return False
        logging.warning("Continuing with changes despite failed deletion.")
    logging.info("Failsafe OK file exists. Proceeding with changes.")
    return True


def write_failsafe_hosts(
    config: ZacSettings, to_add: List[str], to_remove: List[str]
) -> None:
    """Writes a list of hosts to add and remove to a file when the failsafe is reached.

    Uses the failsafe file defined in the config.
    Does nothing if no failsafe file is defined.
    """
    if not config.failsafe_file:
        logging.warning("Unable to write failsafe hosts. No failsafe file configured.")
        return
    h = models.HostActions(add=to_add, remove=to_remove)
    h.write_json(config.failsafe_file)
    logging.info(
        "Wrote list of hosts to add and remove to %s",
        config.failsafe_file,
    )
