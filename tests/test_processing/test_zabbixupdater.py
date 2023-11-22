from pathlib import Path
import time
from unittest.mock import patch
import pytest
import requests

from ..conftest import MockZabbixAPI, PicklableMock
from zabbix_auto_config import exceptions

from zabbix_auto_config.models import ZabbixSettings
from zabbix_auto_config.processing import ZabbixUpdater
from zabbix_auto_config.state import get_manager


def raises_connect_timeout(*args, **kwargs):
    raise requests.exceptions.ConnectTimeout("connect timeout")


# We have to set the side effect in the constructor
class TimeoutAPI(MockZabbixAPI):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.login = PicklableMock(
            side_effect=requests.exceptions.ConnectTimeout("connect timeout")
        )


@pytest.mark.timeout(10)
@patch("pyzabbix.ZabbixAPI", TimeoutAPI())  # mock with timeout on login
def test_zabbixupdater_connect_timeout(mock_psycopg2_connect):
    with pytest.raises(exceptions.ZACException) as exc_info:
        ZabbixUpdater(
            name="connect-timeout",
            db_uri="",
            state=get_manager().State(),
            zabbix_config=ZabbixSettings(
                map_dir="",
                url="",
                username="",
                password="",
                dryrun=False,
                timeout=1,
            ),
        )
    assert "connect timeout" in exc_info.exconly()


class TimeoutUpdater(ZabbixUpdater):
    def do_update(self):
        raise requests.exceptions.ReadTimeout("read timeout")


@pytest.mark.timeout(5)
def test_zabbixupdater_read_timeout(tmp_path: Path, mock_psycopg2_connect):
    # TODO: use mapping file fixtures from #67
    map_dir = tmp_path / "maps"
    map_dir.mkdir()
    (map_dir / "property_template_map.txt").touch()
    (map_dir / "property_hostgroup_map.txt").touch()
    (map_dir / "siteadmin_hostgroup_map.txt").touch()

    process = TimeoutUpdater(
        name="read-timeout",
        db_uri="",
        state=get_manager().State(),
        zabbix_config=ZabbixSettings(
            map_dir=str(map_dir),
            url="",
            username="",
            password="",
            dryrun=False,
            timeout=1,
        ),
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
