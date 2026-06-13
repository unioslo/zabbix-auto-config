from __future__ import annotations

import copy
import ipaddress
import multiprocessing
import queue
import re
from collections.abc import MutableMapping
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import Optional
from typing import Union

import structlog

from zabbix_auto_config.pyzabbix.types import HostTag

if TYPE_CHECKING:
    from zabbix_auto_config._types import ZacTags


logger = structlog.stdlib.get_logger(__name__)


def is_valid_regexp(pattern: str):
    try:
        re.compile(pattern)
        return True
    except (re.error, TypeError):
        return False


def is_valid_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def zabbix_tags2zac_tags(zabbix_tags: list[HostTag]) -> ZacTags:
    return {(tag.tag, tag.value) for tag in zabbix_tags}


def zac_tags2zabbix_tags(zac_tags: ZacTags) -> list[HostTag]:
    return [HostTag(tag=tag[0], value=tag[1]) for tag in zac_tags]


def with_prefix(
    text: str,
    prefix: str,
    separator: str = "-",
) -> str:
    """Replaces the prefix of `text` with `prefix`. Assumes the separator
    between the prefix and the text is `separator` (default: "-").

    Parameters
    ----
    text: str
        The text to format.
    prefix: str
        The prefix to add to `text`.
    separator: str
        The separator between the prefix and the text.

    Returns
    -------
    str
        The formatted string.
    """
    if not all(s for s in (text, prefix, separator)):
        raise ValueError("Text, prefix, and separator cannot be empty")

    _, _, suffix = text.partition(separator)

    # Unable to split text, nothing to do
    if not suffix:
        raise ValueError(
            f"Could not find prefix in {text!r} with separator {separator!r}"
        )

    groupname = f"{prefix}{suffix}"
    if not prefix.endswith(separator) and not suffix.startswith(separator):
        logger.warning(
            "Prefix for group name does not contain separator",
            prefix=prefix,
            groupname=groupname,
            separator=separator,
        )
    return groupname


def mapping_values_with_prefix(
    m: MutableMapping[str, list[str]],
    prefix: str,
    separator: str = "-",
) -> MutableMapping[str, list[str]]:
    """Calls `with_prefix` on all items in the values (list) in the mapping `m`."""
    m = copy.copy(m)  # don't modify the original mapping
    for key, value in m.items():
        new_values = []
        for v in value:
            try:
                new_value = with_prefix(text=v, prefix=prefix, separator=separator)
            except ValueError:
                logger.warning("Unable to replace prefix", text=v, prefix=prefix)
                continue
            new_values.append(new_value)
        m[key] = new_values
    return m


def drain_queue(q: multiprocessing.Queue[Any]) -> None:
    """Drains a multiprocessing.Queue by calling `queue.get_nowait()` until the queue is empty."""
    while not q.empty():
        try:
            q.get_nowait()
        except queue.Empty:
            break


def format_timedelta(td: Optional[timedelta] = None) -> str:
    """Format a timedelta object showing only hours, minutes, and seconds.

    Args:
        td: The timedelta object to format

    Returns:
        A string representation in the format "HH:MM:SS"
    """
    if td is None:
        return "00:00:00"

    # Convert to total seconds and handle sign
    total_seconds = int(td.total_seconds())
    sign = "-" if total_seconds < 0 else ""
    total_seconds = abs(total_seconds)

    # Convert to hours, minutes, seconds
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return f"{sign}{hours:02d}:{minutes:02d}:{seconds:02d}"


def write_file(path: Union[str, Path], content: str, end: str = "\n") -> None:
    """Writes `content` to `path`. Ensures content ends with a given character."""
    path = Path(path)
    # Ensure parent dirs exist
    make_parent_dirs(path)

    try:
        with open(path, "w") as f:
            if end and not content.endswith(end):
                content += end
            f.write(content)
    except OSError as e:
        logger.error("Failed to write to file", file=str(path), error=str(e))
        raise


def make_parent_dirs(path: Union[str, Path]) -> Path:
    """Attempts to create all parent directories given a path.

    NOTE: Intended for usage with Pydantic models, and as such it will raise
    a ValueError instead of OSError if the directory cannot be created."""
    path = Path(path)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise ValueError(f"Failed to create parent directories for {path}: {e}") from e
    return path
