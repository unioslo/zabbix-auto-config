from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable
from typing import List
from unittest.mock import MagicMock

import pytest

from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.failsafe import check_failsafe
from zabbix_auto_config.failsafe import check_failsafe_ok_file
from zabbix_auto_config.failsafe import write_failsafe_hosts
from zabbix_auto_config.models import HostActions
from zabbix_auto_config.models import Settings


@pytest.fixture()
def failsafe_ok_file(tmp_path: Path) -> Iterable[Path]:
    failsafe_file = tmp_path / "failsafe"
    try:
        yield failsafe_file
    finally:
        if failsafe_file.exists():
            failsafe_file.unlink()


@pytest.fixture()
def failsafe_file(tmp_path: Path) -> Iterable[Path]:
    failsafe_file = tmp_path / "failsafe_hosts.json"
    try:
        yield failsafe_file
    finally:
        if failsafe_file.exists():
            failsafe_file.unlink()


FAIL_ZAC = pytest.mark.xfail(strict=True, raises=ZACException)


@pytest.mark.parametrize(
    "failsafe, to_add, to_remove",
    [
        pytest.param(1, ["foo.example.com"], [], id="OK (add)"),
        pytest.param(1, [], ["foo.example.com"], id="OK (remove)"),
        pytest.param(1, ["foo.example.com"], ["bar.example.com"], id="OK (add/remove)"),
        pytest.param(
            3,
            ["foo.example.com", "bar.example.com"],
            ["baz.example.com", "qux.example.com"],
            id="OK (add/remove>1)",
        ),
        pytest.param(
            1,
            ["foo.example.com", "bar.example.com"],
            [],
            id="Fail (add)",
            marks=FAIL_ZAC,
        ),
        pytest.param(
            1,
            [],
            ["foo.example.com", "bar.example.com"],
            id="Fail (remove)",
            marks=FAIL_ZAC,
        ),
        pytest.param(
            1,
            ["foo.example.com"],
            ["bar.example.com", "baz.example.com"],
            id="Fail (add/remove)",
            marks=FAIL_ZAC,
        ),
        pytest.param(
            1,
            ["foo.example.com", "bar.example.com"],
            [],
            id="Fail (add>1)",
            marks=FAIL_ZAC,
        ),
        pytest.param(
            1,
            [],
            ["baz.example.com", "qux.example.com"],
            id="Fail (remove>1)",
            marks=FAIL_ZAC,
        ),
        pytest.param(
            1,
            ["foo.example.com", "bar.example.com"],
            ["baz.example.com", "qux.example.com"],
            id="Fail (add/remove>1)",
            marks=FAIL_ZAC,
        ),
    ],
)
def test_check_failsafe(
    config: Settings, failsafe: int, to_add: List[str], to_remove: List[str]
) -> None:
    config.zabbix.failsafe = failsafe
    check_failsafe(config, to_add, to_remove)


def test_check_failsafe_ok_file_not_configured(config: Settings) -> None:
    """Test that an unconfigured failsafe OK file always returns False"""
    config.zac.failsafe_ok_file = None
    assert check_failsafe_ok_file(config.zac) is False


@pytest.mark.parametrize("content", ["", "1"])
def test_check_failsafe_ok_file_exists(
    failsafe_ok_file: Path, config: Settings, content: str
) -> None:
    """Test that a failsafe ok file that exists is OK with and without content"""
    config.zac.failsafe_ok_file = failsafe_ok_file
    failsafe_ok_file.write_text(content)
    assert check_failsafe_ok_file(config.zac) is True
    # Ensure that approving the file also deletes it
    assert failsafe_ok_file.exists() is False


def test_check_failsafe_ok_file_not_exists(
    failsafe_ok_file: Path, config: Settings
) -> None:
    """Test that a missing failsafe OK file returns False"""
    config.zac.failsafe_file = failsafe_ok_file
    assert failsafe_ok_file.exists() is False
    assert check_failsafe_ok_file(config.zac) is False
    assert failsafe_ok_file.exists() is False  # Should still not exist


@pytest.mark.parametrize("strict", [True, False])
def test_check_failsafe_ok_file_unable_to_delete(
    config: Settings, strict: bool
) -> None:
    """Test a failsafe OK file we are unable to delete."""
    # NOTE: it's quite hard to mock a Path file with a real path
    # so we instead mock the Path object with a MagicMock.
    # An alternative would be to add a function we can pass Path objects
    # to for deletion, then mock that function.
    mock_file = MagicMock(spec=Path)
    mock_file.exists.return_value = True
    mock_file.unlink.side_effect = OSError("Unable to delete file")

    assert mock_file.exists() is True
    config.zac.failsafe_ok_file = mock_file
    config.zac.failsafe_ok_file_strict = strict
    # Fails in strict mode - must be able to delete the file
    if strict:
        assert check_failsafe_ok_file(config.zac) is False
    else:
        assert check_failsafe_ok_file(config.zac) is True


@pytest.mark.parametrize(
    "to_add,to_remove",
    [
        pytest.param(
            ["foo.example.com", "bar.example.com"],
            ["baz.example.com", "qux.example.com"],
            id="Add and remove",
        ),
        pytest.param(["foo.example.com", "bar.example.com"], [], id="Add"),
        pytest.param([], ["baz.example.com", "qux.example.com"], id="Remove"),
        pytest.param([], [], id="No changes"),
    ],
)
@pytest.mark.parametrize("failsafe_file_exists", [True, False])
def test_write_failsafe_hosts(
    config: Settings,
    failsafe_file: Path,
    failsafe_file_exists: bool,
    to_add: list[str],
    to_remove: list[str],
) -> None:
    """Write a list of hosts to a failsafe file."""
    # Ensure we handle both file existing and not existing
    if failsafe_file_exists:
        failsafe_file.write_text("Contains some data")
        assert failsafe_file.exists()
    else:
        assert not failsafe_file.exists()

    # Assign file and write the hosts
    config.zac.failsafe_file = failsafe_file
    write_failsafe_hosts(config.zac, to_add, to_remove)

    # Check contents of file
    assert failsafe_file.exists()
    content = failsafe_file.read_text()
    h = HostActions.model_validate_json(content)
    assert h == HostActions(add=to_add, remove=to_remove)


def test_write_failsafe_hosts_no_file(
    caplog: pytest.LogCaptureFixture, config: Settings
) -> None:
    """Attempt to write failsafe hosts without a failsafe file."""
    caplog.set_level(logging.WARNING)
    config.zac.failsafe_file = None
    write_failsafe_hosts(
        config.zac,
        ["foo.example.com", "bar.example.com"],
        ["baz.example.com", "qux.example.com"],
    )
    assert (
        "No failsafe file configured, cannot write hosts to add/remove."
        in caplog.messages
    )
