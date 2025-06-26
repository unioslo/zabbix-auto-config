"""Santiy testing of Zabbix API version parsing.

Tests against known versions of Zabbix. Expects support for alpha, beta and rc.
"""

from __future__ import annotations

import pytest
from packaging.version import Version


@pytest.mark.parametrize(
    "version, release",
    [
        # Certain major versions released in 2023
        ("7.0.0", (7, 0, 0)),
        ("6.4.8", (6, 4, 8)),
        ("6.0.23", (6, 0, 23)),
        ("5.0.39", (5, 0, 39)),
        ("6.2.9", (6, 2, 9)),
        # Pre-release versions
        ("7.0.0alpha7", (7, 0, 0)),
        ("7.0.0a7", (7, 0, 0)),  # short form
        ("6.4.0beta6", (6, 4, 0)),
        ("6.4.0b6", (6, 4, 0)),  # short form
        ("6.4.8rc1", (6, 4, 8)),
    ],
)
def test_version(version: str, release: tuple[int, int, int]):
    """Test that the version string is parsed correctly."""
    v = Version(version)
    assert v.release == release
    assert v.major == release[0]
    assert v.minor == release[1]
    assert v.micro == release[2]

    # Test comparison
    assert v.release < (999, 999, 999)
    assert v.release > (0, 0, 0)
    assert v > Version("0.0.0")
    assert v < Version("999.999.999")
