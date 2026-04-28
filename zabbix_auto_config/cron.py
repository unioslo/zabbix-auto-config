from __future__ import annotations

import datetime
from typing import Optional

from croniter import croniter


def get_iter(
    schedule: str, start_time: Optional[datetime.datetime] = None
) -> croniter[datetime.datetime]:
    """Get a croniter iterator for a given schedule and start time."""
    if start_time is None:
        start_time = datetime.datetime.now()
    try:
        return croniter(schedule, start_time, datetime.datetime)
    except (ValueError, KeyError) as e:
        raise ValueError(f"Invalid cron schedule: {e}") from e
