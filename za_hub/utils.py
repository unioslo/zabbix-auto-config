import logging
import sys

import pymongo


def handle_database_error(func):
    def wrap(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error("Unable to execute database query")
            sys.exit(1)

    return wrap


def validate_host(host):
    # Host cannot have any other keys than these

    known_keys = [
        "enabled",
        "hostname",
        "importance",
        "interfaces",
        "invertory",
        "macros",
        "roles",
        "siteadmins",
        "source",
    ]

    assert type(host) is dict, "Host is not a dictionary"

    extra_keys = set(host.keys()) - set(known_keys)
    assert len(extra_keys) == 0, f"Host has extra unknown keys: {', '.join(extra_keys)}"

    # Host must have these keys

    assert "enabled" in host, "'enabled' missing from host"
    assert type(host["enabled"]) is bool, "'enabled' is not a bool"
    assert "hostname" in host, "'hostname' missing from host"
    assert type(host["hostname"]) is str, "'hostname' is not a string"
    assert "source" in host, "'source' missing from host"
    assert type(host["source"]) is str, "'source' is not a string"

    # Host may have these keys

    if "importance" in host:
        assert type(host["importance"]) is int, "'importance' is not an integer"

    if "interfaces" in host:
        pass  # TODO: What should interfaces look like?

    if "inventory" in host:
        pass  # TODO: What should inventory look like?

    if "macros" in host:
        pass  # TODO: What should macros look like?

    if "roles" in host:
        assert type(host["roles"]) is list, "'roles' is not a list"
        for role in host["roles"]:
            assert type(role) is str, "Found role that isn't a string"

    if "siteadmins" in host:
        assert type(host["siteadmins"]) is list, "'siteadmins' is not a list"
        for siteadmin in host["siteadmins"]:
            assert type(siteadmin) is str, "Found siteadmin that isn't a string"


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
                logging.warning("Unable to read line in map file: '{line}'")
                continue

            if key in _map:
                _map[key].extend(values)
            else:
                _map[key] = values

    return _map
