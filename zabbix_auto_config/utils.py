import ipaddress
import logging
import re


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


def read_map_file(path):
    _map = {}

    with open(path) as f:
        for line in [s.strip() for s in f.readlines()]:
            if line.startswith("#") or line == "":
                continue

            try:
                key, values = line.split(":")
                values = [s.strip() for s in values.split(",")]
                key = key.strip()
            except ValueError:
                logging.warning("Unable to read line in map file: '%s'", line)
                continue

            if key in _map:
                _map[key].extend(values)
            else:
                _map[key] = values

    return _map
