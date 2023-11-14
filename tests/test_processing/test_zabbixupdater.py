import multiprocessing
from pathlib import Path
import time
from unittest.mock import MagicMock, patch, Mock
import pytest
import requests
from zabbix_auto_config import exceptions

from zabbix_auto_config.models import ZabbixSettings
from zabbix_auto_config.processing import ZabbixUpdater


def raises_connect_timeout(*args, **kwargs):
    raise requests.exceptions.ConnectTimeout("connect timeout")


@pytest.mark.timeout(10)
@patch("psycopg2.connect", MagicMock())  # throwaway mock
def test_zabbixupdater_connect_timeout():
    with pytest.raises(exceptions.ZACException) as exc_info:
        with patch(
            "pyzabbix.ZabbixAPI.login", new_callable=lambda: raises_connect_timeout
        ):
            ZabbixUpdater(
                name="connect-timeout",
                db_uri="",
                state=multiprocessing.Manager().dict(),
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


class PickableMock(MagicMock):
    def __reduce__(self):
        return (MagicMock, ())


@pytest.mark.timeout(5)
@patch("psycopg2.connect", PickableMock())
@patch("pyzabbix.ZabbixAPI", PickableMock())
def test_zabbixupdater_read_timeout(tmp_path: Path):
    # TODO: use mapping file fixtures from #67
    map_dir = tmp_path / "maps"
    map_dir.mkdir()
    (map_dir / "property_template_map.txt").touch()
    (map_dir / "property_hostgroup_map.txt").touch()
    (map_dir / "siteadmin_hostgroup_map.txt").touch()

    process = TimeoutUpdater(
        name="read-timeout",
        db_uri="",
        state=multiprocessing.Manager().dict(),
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
        while process.state["ok"] is True:
            time.sleep(0.1)
        assert process.state["ok"] is False
        process.stop_event.set()
    finally:
        process.join(timeout=0.01)
