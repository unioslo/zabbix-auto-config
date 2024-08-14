from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest
from httpx import ConnectTimeout
from httpx import ReadTimeout

from zabbix_auto_config import exceptions
from zabbix_auto_config.models import Settings
from zabbix_auto_config.models import ZabbixSettings
from zabbix_auto_config.processing import ZabbixUpdater
from zabbix_auto_config.state import get_manager

from ..conftest import MockZabbixAPI
from ..conftest import PicklableMock


def raises_connect_timeout(*args, **kwargs):
    raise ConnectTimeout("connect timeout")


# We have to set the side effect in the constructor
class TimeoutAPI(MockZabbixAPI):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.login = PicklableMock(side_effect=ConnectTimeout("connect timeout"))


@pytest.mark.timeout(10)
@patch(
    "zabbix_auto_config.processing.ZabbixAPI", TimeoutAPI()
)  # mock with timeout on login
def test_zabbixupdater_connect_timeout(
    mock_psycopg2_connect, config: Settings, map_dir_with_files: Path
):
    config.zabbix = ZabbixSettings(
        map_dir=str(map_dir_with_files),
        url="",
        username="",
        password="",
        dryrun=False,
        timeout=1,
    )
    with pytest.raises(exceptions.ZACException) as exc_info:
        ZabbixUpdater(
            name="connect-timeout",
            db_uri="",
            state=get_manager().State(),
            settings=config,
        )
    assert "connect timeout" in exc_info.exconly()


class TimeoutUpdater(ZabbixUpdater):
    def do_update(self):
        raise ReadTimeout("read timeout")


@pytest.mark.timeout(5)
def test_zabbixupdater_read_timeout(
    mock_psycopg2_connect, config: Settings, map_dir_with_files: Path
):
    config.zabbix = ZabbixSettings(
        map_dir=str(map_dir_with_files.absolute()),
        url="",
        username="",
        password="",
        dryrun=False,
        timeout=1,
    )
    process = TimeoutUpdater(
        name="read-timeout",
        db_uri="",
        state=get_manager().State(),
        settings=config,
    )

    # Start the process and wait for it to be marked as unhealthy
    try:
        process.start()
        while process.state.ok is True:
            time.sleep(0.1)
        assert process.state.ok is False
        assert process.state.error_type == "ReadTimeout"
        assert process.state.error_count == 1
        process.stop_event.set()
    finally:
        process.join(timeout=0.01)
