import multiprocessing
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from zabbix_auto_config.models import Host, PropertyTaggingSettings, ZabbixSettings

from zabbix_auto_config.processing import ZabbixHostUpdater


@pytest.fixture(name="zabbix_settings")
def _zabbix_settings(map_dir_with_files: Path) -> ZabbixSettings:
    return ZabbixSettings(
        map_dir=str(map_dir_with_files),
        url="http://localhost",
        username="Admin",
        password="zabbix",
        dryrun=False,
        failsafe=20,
        tags_prefix="zac_",
        managed_inventory=[],
        property_tagging=PropertyTaggingSettings(
            enabled=True,
            tag="property",
            include=[],
            exclude=[],
        ),
    )


@patch("psycopg2.connect", MagicMock())
@patch("pyzabbix.ZabbixAPI", MagicMock())
def test_set_property_tags(zabbix_settings: ZabbixSettings):
    """Tests set_property_tags() with a host that has 1 unmanaged tag and 1 managed tag.

    We expect the unamanged tag to be kept, while the managed tag is removed
    due to no corresponding host property.
    """
    process = ZabbixHostUpdater(
        "test-zabbix-host-updater",
        multiprocessing.Manager().dict(),
        "postgresql://localhost:5432/zabbix",
        zabbix_config=zabbix_settings,
    )

    db_host = Host(
        hostname="foo.example.com",
        enabled=True,
        properties=["is_app_server", "is_adfs_server"],
        tags=[("zac_tag1", "tag1value")],
    )
    zabbix_host = {
        "name": "foo.example.com",
        "host": "foo.example.com",
        "hostid": "123",
        "tags": [
            {"tag": "zac_tag1", "value": "tag1value"},
            {"tag": "property", "value": "will_be_removed"},
        ],
    }
    process.set_property_tags(db_host, zabbix_host)
    assert process.api.host.update.call_count == 1
    assert process.api.host.update.call_args.kwargs["hostid"] == "123"
    tags_kwarg = process.api.host.update.call_args.kwargs["tags"]
    assert len(tags_kwarg) == 3
    assert {"tag": "zac_tag1", "value": "tag1value"} in tags_kwarg
    assert {"tag": "property", "value": "is_adfs_server"} in tags_kwarg
    assert {"tag": "property", "value": "is_app_server"} in tags_kwarg
    assert {"tag": "property", "value": "will_be_removed"} not in tags_kwarg
