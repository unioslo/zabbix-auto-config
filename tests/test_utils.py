import logging
from pathlib import Path

import pytest
from zabbix_auto_config import utils


def test_read_map_file(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    tmpfile = tmp_path / "map.txt"
    tmpfile.write_text(
        "\n".join(
            [
                "key1:val1",
                "key2:val2,val3",
                "invalid line here",  # warning (no colon)
                "key3:val4",
                "key3:val5",
                "key4:",
                "key5: ",
                "key6:,",
                "# this is a comment",  # ignored (comment)
                "key7:val7,",
                "key8:val8:val9",  # warning (invalid format)
                "",  # ignored (empty line)
            ]
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        m = utils.read_map_file(tmpfile)

    assert m == {
        "key1": ["val1"],
        "key2": ["val2", "val3"],
        "key3": ["val4", "val5"],
        "key4": [""],
        "key5": [""],
        "key6": ["", ""],
        "key7": ["val7", ""],
    }
    invalid_lines_contain = ["invalid line here", "key8:val8:val9"]
    for phrase in invalid_lines_contain:
        assert phrase in caplog.text
    assert caplog.text.count("WARNING") == 2
