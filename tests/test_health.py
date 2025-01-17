from __future__ import annotations

import datetime

import pytest
from zabbix_auto_config.health import HealthFile
from zabbix_auto_config.health import ProcessInfo
from zabbix_auto_config.state import State
from zabbix_auto_config.state import get_manager


@pytest.mark.parametrize("use_manager", [True, False])
def test_healthfile_to_json(use_manager: bool) -> None:
    # Test with and without proxied classes
    if use_manager:
        man = get_manager()
        s = man.State()
    else:
        s = State()

    health_file = HealthFile(
        date=datetime.datetime(2021, 1, 1, 0, 0, 0),
        cwd="/path/to/zac",
        pid=1234,
        failsafe=123,
        processes=[
            ProcessInfo(
                name="test_process",
                pid=1235,
                alive=True,
                state=s,
            )
        ],
    )

    # Check that we can call to_json() without errors
    assert health_file.to_json()
