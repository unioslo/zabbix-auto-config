from __future__ import annotations

from pathlib import Path

import structlog
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from inline_snapshot import snapshot
from zabbix_auto_config.map_file import MapFile


def test_read_map_file(tmp_path: Path, log_output: structlog.testing.LogCapture):
    tmpfile = tmp_path / "map.txt"
    tmpfile.write_text(
        """\
a:1
b:2,3
invalid line here # WARNING: no colon
c:4
d:6
e:  # WARNING: no value after colon
f:  # WARNING: no value
g:,  # WARNING: no value + trailing comma
# this is a comment # IGNORED: comment
h:6,    # OK: trailing comma
h:6     # WARNING: duplicate key+value
i:7:8   # OK: colon in value
j:9,9,10 # WARNING: duplicate values
k :11,12,13 # OK: whitespace before colon
l: 14 , 15,16 # OK: leading and trailing whitespace in values
l:17 # WARNING: duplicate key (extends existing values)

# More complex cases
Spaces in key: Spaces in values, are, ok
""",
        encoding="utf-8",
    )

    m = MapFile(path=tmpfile, name="Test map file").read()

    assert m == snapshot(
        {
            "a": ["1"],
            "b": ["2", "3"],
            "c": ["4"],
            "d": ["6"],
            "h": ["6"],
            "i": ["7:8"],
            "j": ["9", "10"],
            "k": ["11", "12", "13"],
            "l": ["14", "15", "16", "17"],
            "Spaces in key": ["Spaces in values", "are", "ok"],
        }
    )

    # Test logging output

    # Invalid lines
    lines = [
        "invalid line here",
        "e:",
        "f:",
        "g:,",
    ]
    for line in lines:
        assert any(line == event.get("line") for event in log_output.entries), (
            f"Expected line '{line}' in log output {log_output.entries}"
        )

    # Parsed keys with warnings/errors
    keys = [
        "h",
        "j",
    ]
    for key in keys:
        assert any(key == event.get("key") for event in log_output.entries), (
            f"Expected key '{key}' in log output {log_output.entries}"
        )

    # Line numbers where warnings/errors were logged
    lines = [3, 6, 7, 8, 11, 16]
    for lineno in lines:
        assert any(lineno == event["lineno"] for event in log_output.entries), (
            f"Expected line number {lineno} in log output"
        )


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
    m = MapFile(path=tmpfile, name="Test map file").read()
    for key in m:
        assert key  # no empty keys
        for value in m[key]:
            assert value  # no empty values
