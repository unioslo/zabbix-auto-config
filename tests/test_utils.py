from ipaddress import IPv4Address, IPv6Address
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Union

import pytest
from zabbix_auto_config import utils
from hypothesis import given, settings, strategies as st, HealthCheck, assume


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
            [{"tag": "tag1", "value": "x"}],
            {("tag1", "x")},
        ),
        (
            [{"tag": "tag1", "value": "x"}, {"tag": "tag2", "value": "y"}],
            {("tag1", "x"), ("tag2", "y")},
        ),
        (
            [{"tag": "tag1", "value": "x", "foo": "tag2", "bar": "y"}],
            {("tag1", "x", "tag2", "y")},
        ),
    ],
)
def test_zabbix_tags2zac_tags(
    tags: List[Dict[str, str]], expected: Set[Tuple[str, str]]
):
    assert utils.zabbix_tags2zac_tags(tags) == expected


@pytest.mark.parametrize(
    "tags,expected",
    [
        (
            {("tag1", "x")},
            [{"tag": "tag1", "value": "x"}],
        ),
        (
            {("tag1", "x"), ("tag2", "y")},
            [{"tag": "tag1", "value": "x"}, {"tag": "tag2", "value": "y"}],
        ),
        (
            {("tag1", "x", "tag2", "y")},
            [{"tag": "tag1", "value": "x"}],
        ),
    ],
)
def test_zac_tags2zabbix_tags(
    tags: Set[Tuple[str, str]], expected: List[Dict[str, str]]
):
    zabbix_tags = utils.zac_tags2zabbix_tags(tags)
    for tag in expected:
        assert tag in zabbix_tags
