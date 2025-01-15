from __future__ import annotations

import datetime

from zabbix_auto_config.health import HealthFile
from zabbix_auto_config.health import ProcessInfo
from zabbix_auto_config.state import State


def test_healthfile_to_json() -> None:
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
                state=State(
                    ok=False,
                    error="Test error",
                    error_type="CustomException",
                    error_count=1,
                    error_time=1736951323.874142,
                    execution_count=3,
                    total_duration=datetime.timedelta(seconds=4),
                    max_duration=datetime.timedelta(seconds=2),
                    last_duration_warning=datetime.datetime(2021, 1, 2, 0, 0, 0),
                ),
            )
        ],
    )

    # Check that we can call to_json() without errors
    assert health_file.to_json()
