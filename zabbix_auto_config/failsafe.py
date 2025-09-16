from __future__ import annotations

import structlog

from zabbix_auto_config import models
from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.models import Settings
from zabbix_auto_config.models import ZacSettings

logger = structlog.stdlib.get_logger(__name__)


def check_failsafe(config: Settings, to_add: list[str], to_remove: list[str]) -> None:
    """Check if number of hosts to add/remove exceeds the failsafe and handle appropriately."""
    failsafe = config.zabbix.failsafe
    if len(to_remove) <= failsafe and len(to_add) <= failsafe:
        return

    # Failsafe exceeded - check for failsafe OK file
    if check_failsafe_ok_file(config.zac):
        return

    # Failsafe OK file validation failed
    # We must write the hosts to add/remove and raise an exception
    write_failsafe_hosts(config.zac, to_add, to_remove)
    logger.warning(
        "Too many hosts to change (failsafe=%d). Remove: %d, Add: %d. Aborting",
        failsafe,
        len(to_remove),
        len(to_add),
    )
    raise ZACException("Failsafe triggered")


def check_failsafe_ok_file(config: ZacSettings) -> bool:
    """Check the failsafe OK file and returns True if application should proceed.

    Attempts to delete the failsafe OK file if it exists.
    Depending on the configuration, succeeding in deleting the file may
    be required to proceed with changes."""
    # Check for presence of file
    if not config.failsafe_ok_file:
        logger.info("No failsafe OK file configured.")
        return False
    log = logger.bind(file=str(config.failsafe_ok_file))
    if not config.failsafe_ok_file.exists():
        log.warning(
            "Failsafe OK file does not exist. Create it to approve changes. The ZAC process must have permission to delete the file."
        )
        return False
    # File exists, attempt to delete it
    try:
        config.failsafe_ok_file.unlink()
    except OSError as e:
        log.error("Unable to delete failsafe OK file", error=str(e))
        if config.failsafe_ok_file_strict:
            return False  # failed to delete in strict mode
        # NOTE: should this be an INFO or DEBUG log instead?
        log.warning("Continuing with changes despite failed deletion.")
    log.info("Failsafe OK file exists. Proceeding with changes.")
    return True


def write_failsafe_hosts(
    config: ZacSettings, to_add: list[str], to_remove: list[str]
) -> None:
    """Write a list of hosts to add and remove to a file when the failsafe is reached.

    Uses the failsafe file defined in the config.
    Does nothing if no failsafe file is defined.
    """

    if not config.failsafe_file:
        logger.warning("No failsafe file configured, cannot write hosts to add/remove.")
        return
    log = logger.bind(file=str(config.failsafe_file))
    h = models.HostActions(add=to_add, remove=to_remove)
    h.write_json(config.failsafe_file)
    log.info("Wrote list of hosts to add and remove", file=config.failsafe_file)
