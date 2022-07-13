import ipaddress
import logging
from pathlib import Path
import re
from typing import Dict, Iterable, List, Sequence, Set, Tuple, Union


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
