import copy
import ipaddress
import logging
import multiprocessing
from pathlib import Path
import queue
import re
from typing import Dict, Iterable, List, Mapping, MutableMapping, Set, Tuple, Union

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


def zabbix_tags2zac_tags(zabbix_tags: Iterable[Dict[str, str]]) -> Set[Tuple[str, ...]]:
    return {tuple(tag.values()) for tag in zabbix_tags}


def zac_tags2zabbix_tags(zac_tags: Iterable[Tuple[str, str]]) -> List[Dict[str, str]]:
    zabbix_tags = [{"tag": tag[0], "value": tag[1]} for tag in zac_tags]
    return zabbix_tags


def read_map_file(path: Union[str, Path]) -> Dict[str, List[str]]:
    _map = {}  # type: Dict[str, List[str]]

    with open(path) as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()

            # empty line or comment
            if not line or line.startswith("#"):
                continue

            try:
                key, value = line.split(":", 1)

                # Remove whitespace and check for empty key
                key = key.strip()
                if not key:
                    raise ValueError(f"Emtpy key on line {lineno} in map file {path}")

                # Split on comma, but only keep non-empty values
                values = list(filter(None, [s.strip() for s in value.split(",")]))
                if not values or all(not s for s in values):
                    raise ValueError(
                        f"Empty value(s) on line {lineno} in map file {path}"
                    )
            except ValueError:
                logging.warning(
                    "Invalid format at line {lineno} in map file '{path}'. Expected 'key:value', got '{line}'.".format(
                        lineno=lineno, path=path, line=line
                    ),
                )
                continue

            if key in _map:
                logging.warning(
                    "Duplicate key {key} at line {lineno} in map file '{path}'.".format(
                        key=key, lineno=lineno, path=path
                    )
                )
                _map[key].extend(values)
            else:
                _map[key] = values

    # Final pass to remove duplicate values
    for key, values in _map.items():
        values_dedup = list(dict.fromkeys(values))  # dict.fromkeys() guarantees order
        if len(values) != len(values_dedup):
            logging.warning(
                "Ignoring duplicate values for key '{key}' in map file '{path}'.".format(
                    key=key, path=path
                )
            )
        _map[key] = values_dedup
    return _map


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
        logging.warning(
            "Prefix '%s' for group name '%s' does not contain separator '%s'",
            prefix,
            groupname,
            separator,
        )
    return groupname

def mapping_values_with_prefix(
    m: MutableMapping[str, List[str]],
    prefix: str,
    separator: str = "-",
) -> MutableMapping[str, List[str]]:
    """Calls `with_prefix` on all items in the values (list) in the mapping `m`."""
    m = copy.copy(m) # don't modify the original mapping
    for key, value in m.items():
        new_values = []
        for v in value:
            try:
                new_value = with_prefix(text=v, prefix=prefix, separator=separator)
            except ValueError:
                logging.warning(
                    f"Unable to replace prefix in '%s' with '%s'", v, prefix
                )
                continue
            new_values.append(new_value)
        m[key] = new_values
    return m


def drain_queue(q: multiprocessing.Queue) -> None:
    """Drains a multiprocessing.Queue by calling `queue.get_nowait()` until the queue is empty."""
    while not q.empty():
        try:
            q.get_nowait()
        except queue.Empty:
            break
