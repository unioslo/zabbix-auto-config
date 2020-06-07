import logging
import re


def is_valid_regexp(pattern):
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def validate_host(host):
    # Host cannot have any other keys than these

    known_keys = [
        "enabled",
        "hostname",
        "importance",
        "interfaces",
        "inventory",
        "macros",
        "properties",
        "proxy_pattern",
        "siteadmins",
        "sources"
    ]

    assert isinstance(host, dict), "Host is not a dictionary"

    extra_keys = set(host.keys()) - set(known_keys)
    assert len(extra_keys) == 0, f"Host has extra unknown keys: {', '.join(extra_keys)}"

    # Host must have these keys

    assert "enabled" in host, "'enabled' missing from host"
    assert isinstance(host["enabled"], bool), "'enabled' is not a bool"

    assert "hostname" in host, "'hostname' missing from host"
    assert isinstance(host["hostname"], str), "'hostname' is not a string"

    assert "sources" in host, "'sources' missing from host"
    assert isinstance(host["sources"], list), "'sources' is not a list"
    for source in host["sources"]:
        assert isinstance(source, str), "Found source that isn't a string"

    # Host may have these keys

    if "importance" in host:
        assert isinstance(host["importance"], int), "'importance' is not an integer"

    if "interfaces" in host:
        pass  # TODO: What should interfaces look like?

    if "inventory" in host:
        pass  # TODO: What should inventory look like?

    if "macros" in host:
        pass  # TODO: What should macros look like?

    if "properties" in host:
        assert isinstance(host["properties"], list), "'properties' is not a list"
        for _property in host["properties"]:
            assert isinstance(_property, str), "Found property that isn't a string"

    if "proxy_pattern" in host:
        assert is_valid_regexp(host["proxy_pattern"])

    if "siteadmins" in host:
        assert isinstance(host["siteadmins"], list), "'siteadmins' is not a list"
        for siteadmin in host["siteadmins"]:
            assert isinstance(siteadmin, str), "Found siteadmin that isn't a string"


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
                logging.warning(f"Unable to read line in map file: '{line}'")
                continue

            if key in _map:
                _map[key].extend(values)
            else:
                _map[key] = values

    return _map
