from __future__ import annotations

import logging
from datetime import timedelta
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from pathlib import Path
from typing import Union

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest import LogCaptureFixture
from zabbix_auto_config import utils
from zabbix_auto_config.pyzabbix.types import HostTag


@pytest.mark.parametrize(
    "input,expected",
    [
        (r"\d", True),
        (r"\D", True),
        (r"\z", False),
        (r"hello", True),
        (r"\.", True),
        (r"\(", True),
        (r"\)", True),
    ],
)
def test_is_valid_regexp(input: str, expected: bool):
    assert utils.is_valid_regexp(input) == expected


@given(st.ip_addresses())
def test_is_valid_ip(ip_address: Union[IPv4Address, IPv6Address]):
    assert utils.is_valid_ip(str(ip_address))


def test_read_map_file(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    tmpfile = tmp_path / "map.txt"
    tmpfile.write_text(
        "\n".join(
            [
                "a:1",
                "b:2,3",
                "invalid line here",  # warning (no colon)
                "c:4",
                "d:5",
                "e:",
                "f: ",
                "g:,",
                "# this is a comment",  # ignored (comment)
                "h:6,",
                "h:6",  # duplicate key+value
                "i:7:8",  # colon in value (allowed)
                "j:9,9,10",  # duplicate values
                "k :11,12,13",  # trailing whitespace in key
                "l: 14 , 15,16 ",  # leading and trailing whitespace in values
                "l:17",  # duplicate key (extends existing values)
                "",  # ignored (empty line)
            ]
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        m = utils.read_map_file(tmpfile)

    assert m == {
        "a": ["1"],
        "b": ["2", "3"],
        "c": ["4"],
        "d": ["5"],
        "h": ["6"],
        "i": ["7:8"],
        "j": ["9", "10"],
        "k": ["11", "12", "13"],
        "l": ["14", "15", "16", "17"],
    }
    invalid_lines_contain = [
        "'invalid line here'",
        "'e:'",
        "'f:'",
        "'g:,'",
        "duplicate values",
        "Duplicate key",
        "key 'h'",
        "key 'j'",
        # Check correct line numbers
        "line 3",
        "line 6",
        "line 7",
        "line 8",
        "line 11",
        "line 16",
    ]
    for phrase in invalid_lines_contain:
        assert phrase in caplog.text
    assert caplog.text.count("WARNING") == 8


@given(st.text())
@settings(
    max_examples=1000,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_read_map_file_fuzz(tmp_path: Path, text: str):
    tmpfile = tmp_path / "map_fuzz.txt"
    tmpfile.write_text(
        text,
        encoding="utf-8",
    )
    m = utils.read_map_file(tmpfile)
    for key in m:
        assert key  # no empty keys
        for value in m[key]:
            assert value  # no empty values


@pytest.mark.parametrize(
    "tags,expected",
    [
        (
            [HostTag(tag="tag1", value="x")],
            {("tag1", "x")},
        ),
        (
            [HostTag(tag="tag1", value="x"), HostTag(tag="tag2", value="y")],
            {("tag1", "x"), ("tag2", "y")},
        ),
    ],
)
def test_zabbix_tags2zac_tags(tags: list[HostTag], expected: set[tuple[str, str]]):
    assert utils.zabbix_tags2zac_tags(tags) == expected


@pytest.mark.parametrize(
    "tags,expected",
    [
        (
            {("tag1", "x")},
            [HostTag(tag="tag1", value="x")],
        ),
        (
            {("tag1", "x"), ("tag2", "y")},
            [HostTag(tag="tag1", value="x"), HostTag(tag="tag2", value="y")],
        ),
        (
            {("tag1", "x", "tag2", "y")},
            [HostTag(tag="tag1", value="x")],
        ),
    ],
)
def test_zac_tags2zabbix_tags(
    tags: set[tuple[str, str]], expected: list[dict[str, str]]
):
    zabbix_tags = utils.zac_tags2zabbix_tags(tags)
    for tag in expected:
        assert tag in zabbix_tags


# Test with the two prefixes we use + no prefix
@pytest.mark.parametrize(
    "prefix",
    ["Templates-", "Siteadmin-"],
)
def test_mapping_values_with_prefix(hostgroup_map_file: Path, prefix: str):
    m = utils.read_map_file(hostgroup_map_file)

    # Make sure we read the map file correctly
    assert len(m) == 3

    old_prefix = "Hostgroup-"
    new_map = utils.mapping_values_with_prefix(
        m,
        prefix=prefix,
    )

    # Compare new dict to old dict
    assert new_map is not m  # we should get a new dict
    assert len(new_map) == len(m)
    assert sum(len(v) for v in new_map.values()) == sum(len(v) for v in m.values())

    # Check values in new map
    assert new_map["user1@example.com"] == [f"{prefix}user1-primary"]
    assert new_map["user2@example.com"] == [
        f"{prefix}user2-primary",
        f"{prefix}user2-secondary",
    ]
    assert new_map["user3@example.com"] == [f"{prefix}user3-primary"]

    # Check values in old map (they should be untouched)
    assert m["user1@example.com"] == [f"{old_prefix}user1-primary"]
    assert m["user2@example.com"] == [
        f"{old_prefix}user2-primary",
        f"{old_prefix}user2-secondary",
    ]
    assert m["user3@example.com"] == [f"{old_prefix}user3-primary"]


def test_mapping_values_with_prefix_no_prefix_arg(caplog: LogCaptureFixture) -> None:
    """Passing an empty string as the prefix should be ignored and logged."""
    res = utils.mapping_values_with_prefix(
        {"user1@example.com": ["Hostgroup-user1-primary"]},
        prefix="",
    )
    assert res == {"user1@example.com": []}
    assert caplog.text.count("WARNING") == 1


def test_mapping_values_with_prefix_no_group_prefix(caplog: LogCaptureFixture) -> None:
    """Passing a group name with no prefix separated by the separator
    should be ignored and logged."""
    res = utils.mapping_values_with_prefix(
        {"user1@example.com": ["Mygroup"]},
        prefix="Foo-",
    )
    assert res == {"user1@example.com": []}
    assert caplog.text.count("WARNING") == 1


def test_mapping_values_with_prefix_no_prefix_separator(
    caplog: LogCaptureFixture,
) -> None:
    """Passing a prefix with no separator emits a warning (but is otherwise legal)."""
    res = utils.mapping_values_with_prefix(
        {"user1@example.com": ["Hostgroup-user1-primary", "Hostgroup-user1-secondary"]},
        prefix="Foo",
    )
    assert res == {"user1@example.com": ["Foouser1-primary", "Foouser1-secondary"]}
    assert caplog.text.count("WARNING") == 2


@pytest.mark.parametrize(
    "inp,expected",
    [
        # Normal cases
        (timedelta(hours=1, minutes=30, seconds=45), "01:30:45"),
        (timedelta(hours=0, minutes=5, seconds=30), "00:05:30"),
        (timedelta(hours=24, minutes=0, seconds=0), "24:00:00"),
        # Zero and near-zero cases
        (timedelta(seconds=0), "00:00:00"),
        (timedelta(microseconds=999999), "00:00:00"),  # Should truncate to zero
        # Negative durations
        (timedelta(hours=-1, minutes=-30, seconds=-45), "-01:30:45"),
        (timedelta(hours=-2), "-02:00:00"),
        # Large durations (multiple days)
        (timedelta(days=1, hours=2, minutes=3, seconds=4), "26:03:04"),
        (timedelta(days=2), "48:00:00"),
        # Fractional components
        (timedelta(hours=1, minutes=30, seconds=45, microseconds=500000), "01:30:45"),
        # None case
        (None, "00:00:00"),
        # Edge cases around zero
        (timedelta(microseconds=1), "00:00:00"),
        (timedelta(microseconds=-1), "00:00:00"),
        # Mixed positive/negative components
        (timedelta(hours=1, minutes=-30), "00:30:00"),  # Python normalizes this
        # Large negative durations
        (timedelta(days=-2, hours=-3), "-51:00:00"),
    ],
)
def test_format_timedelta(inp: timedelta, expected: str):
    assert utils.format_timedelta(inp) == expected
