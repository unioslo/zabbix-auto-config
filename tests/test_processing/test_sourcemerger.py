import multiprocessing
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from zabbix_auto_config.models import Host, Settings
from zabbix_auto_config.processing import SourceMergerProcess


@pytest.mark.parametrize("dryrun", [True, False])
@patch("psycopg2.connect", MagicMock())
@patch("pyzabbix.ZabbixAPI", MagicMock())
def test_set_property_tags(config: Settings, dryrun: bool):
    """Tests set_property_tags() with a host that has 1 unmanaged tag and 1 managed tag.

    We expect the unamanged tag to be kept, while the managed tag is removed
    due to no corresponding host property.
    """
    config.zabbix.dryrun = dryrun

    config.zabbix.property_tagging.tag = "property"
    config.zabbix.tags_prefix = "zac_"

    process = SourceMergerProcess(
        "test-zabbix-host-updater",
        multiprocessing.Manager().dict(),
        config,
    )

    host = Host(
        hostname="foo.example.com",
        enabled=True,
        properties=["is_app_server", "is_adfs_server"],
        tags=[("zac_tag1", "tag1value")],
    )
    host_tags_pre = host.tags.copy()
    process.set_property_tags(host)

    if not dryrun:
        assert len(host.tags) == 3
        assert ("zac_tag1", "tag1value") in host.tags  # existing tag is kept
        assert ("zac_property", "is_adfs_server") in host.tags
        assert ("zac_property", "is_app_server") in host.tags
    else:
        assert host.tags == host_tags_pre
