import ipaddress
import logging
from pathlib import Path
import re
from typing import Dict, List, Union


def is_valid_regexp(pattern):
    try:
        re.compile(pattern)
        return True
    except (re.error, TypeError):
        return False


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def zabbix_tags2zac_tags(zabbix_tags):
    return {tuple(tag.values()) for tag in zabbix_tags}


def zac_tags2zabbix_tags(zac_tags):
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

                # Remove whitespace and check for empty key/values
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
                    "Invalid format at line {} in map file. Expected 'key:value', got '{}'.".format(
                        lineno, line
                    ),
                )
                continue

            # Remove duplicates (dict.fromkeys guarantees order unlike list(set()))
            values_dedup = list(dict.fromkeys(values))
            if len(values) != len(values_dedup):
                logging.warning(
                    "Ignoring duplicate values at line {} in map file.".format(lineno)
                )
                values = values_dedup

            if key in _map:
                logging.warning(
                    "Duplicate key {} at line {} in map file.".format(key, lineno)
                )
                _map[key].extend(values)
            else:
                _map[key] = values
    return _map
