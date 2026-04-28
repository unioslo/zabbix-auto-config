from __future__ import annotations

from datetime import datetime

import pytest

from zabbix_auto_config.cron import get_iter

START_TIME = datetime(2021, 1, 1, 0, 0, 0)  # Friday


@pytest.mark.parametrize(
    "schedule,values",
    [
        (
            "* * * * *",  # every minute
            [
                datetime(2021, 1, 1, 0, 1, 0),
                datetime(2021, 1, 1, 0, 2, 0),
                datetime(2021, 1, 1, 0, 3, 0),
                datetime(2021, 1, 1, 0, 4, 0),
                datetime(2021, 1, 1, 0, 5, 0),
            ],
        ),
        (
            "0 * * * *",  # every hour
            [
                datetime(2021, 1, 1, 1, 0, 0),
                datetime(2021, 1, 1, 2, 0, 0),
                datetime(2021, 1, 1, 3, 0, 0),
                datetime(2021, 1, 1, 4, 0, 0),
                datetime(2021, 1, 1, 5, 0, 0),
            ],
        ),
        (
            "*/15 * * * *",  # every 15 minutes
            [
                datetime(2021, 1, 1, 0, 15, 0),
                datetime(2021, 1, 1, 0, 30, 0),
                datetime(2021, 1, 1, 0, 45, 0),
                datetime(2021, 1, 1, 1, 0, 0),
                datetime(2021, 1, 1, 1, 15, 0),
            ],
        ),
        (
            "5 4 * * *",  # daily at 04:05
            [
                datetime(2021, 1, 1, 4, 5, 0),
                datetime(2021, 1, 2, 4, 5, 0),
                datetime(2021, 1, 3, 4, 5, 0),
                datetime(2021, 1, 4, 4, 5, 0),
                datetime(2021, 1, 5, 4, 5, 0),
            ],
        ),
        (
            "0 0 * * *",  # daily at midnight
            [
                datetime(2021, 1, 2, 0, 0, 0),
                datetime(2021, 1, 3, 0, 0, 0),
                datetime(2021, 1, 4, 0, 0, 0),
                datetime(2021, 1, 5, 0, 0, 0),
                datetime(2021, 1, 6, 0, 0, 0),
            ],
        ),
        (
            "0 9 * * 1-5",  # weekdays at 09:00; 2021-01-01 is a Friday
            [
                datetime(2021, 1, 1, 9, 0, 0),  # Friday
                datetime(2021, 1, 4, 9, 0, 0),  # Monday
                datetime(2021, 1, 5, 9, 0, 0),  # Tuesday
                datetime(2021, 1, 6, 9, 0, 0),  # Wednesday
                datetime(2021, 1, 7, 9, 0, 0),  # Thursday
            ],
        ),
        (
            "30 6 * * 0",  # every Sunday at 06:30; next Sunday from start is 2021-01-03
            [
                datetime(2021, 1, 3, 6, 30, 0),
                datetime(2021, 1, 10, 6, 30, 0),
                datetime(2021, 1, 17, 6, 30, 0),
                datetime(2021, 1, 24, 6, 30, 0),
                datetime(2021, 1, 31, 6, 30, 0),
            ],
        ),
        (
            "0 0 1 * *",  # first day of each month at midnight
            [
                datetime(2021, 2, 1, 0, 0, 0),
                datetime(2021, 3, 1, 0, 0, 0),
                datetime(2021, 4, 1, 0, 0, 0),
                datetime(2021, 5, 1, 0, 0, 0),
                datetime(2021, 6, 1, 0, 0, 0),
            ],
        ),
    ],
)
def test_get_iter(schedule: str, values: list[datetime]):
    citer = get_iter(schedule, start_time=START_TIME)
    for expected in values:
        assert citer.get_next() == expected


@pytest.mark.parametrize(
    "schedule",
    [
        "not a cron",
        "* * * *",  # too few fields
        "60 * * * *",  # minute out of range
        "* 25 * * *",  # hour out of range
    ],
)
def test_get_iter_invalid(schedule: str):
    with pytest.raises(ValueError, match="Invalid cron schedule"):
        _ = get_iter(schedule)
