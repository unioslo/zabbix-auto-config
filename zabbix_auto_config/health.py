from __future__ import annotations

import logging
import multiprocessing
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Optional

from pydantic import BaseModel
from pydantic import Field
from pydantic import computed_field
from pydantic import field_serializer
from pydantic import field_validator

from zabbix_auto_config import processing
from zabbix_auto_config.state import State
from zabbix_auto_config.state import StateProxy

logger = logging.getLogger(__name__)


class ProcessInfo(BaseModel):
    name: str
    pid: Optional[int]
    alive: bool
    state: State

    @field_validator("state", mode="before")
    @classmethod
    def validate_state(cls, value: State) -> Any:
        if isinstance(value, StateProxy):
            return value._getvalue()
        return value


class QueueInfo(BaseModel):
    size: int


class HealthFile(BaseModel):
    """Health file for the application."""

    date: datetime = Field(default_factory=datetime.now)
    cwd: str
    pid: int
    processes: list[ProcessInfo] = []
    queues: list[QueueInfo] = []
    failsafe: int

    @computed_field
    @property
    def date_unixtime(self) -> int:
        return int(self.date.timestamp())

    @computed_field
    @property
    def all_ok(self) -> bool:
        return all(p.alive for p in self.processes)

    @field_serializer("date", when_used="json")
    def serialize_date(self, value: datetime) -> str:
        return value.isoformat(timespec="seconds")

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)


def write_health(
    health_file: Path,
    processes: list[processing.BaseProcess],
    queues: list[multiprocessing.Queue],
    failsafe: int,
) -> None:
    health = HealthFile(
        cwd=os.getcwd(),
        pid=os.getpid(),
        failsafe=failsafe,
    )

    for process in processes:
        health.processes.append(
            ProcessInfo(
                name=process.name,
                pid=process.pid,
                alive=process.is_alive(),
                state=process.state,
            )
        )

    for queue in queues:
        health.queues.append(
            QueueInfo(
                size=queue.qsize(),
            )
        )

    try:
        with open(health_file, "w") as f:
            f.write(health.to_json())
    except Exception as e:
        logger.error("Unable to write health file %s: %s", health_file, e)
