from __future__ import annotations

import time
import types
from dataclasses import asdict
from dataclasses import field
from datetime import datetime
from datetime import timedelta
from multiprocessing.managers import BaseManager
from multiprocessing.managers import NamespaceProxy  # type: ignore # why unexported?
from typing import Any
from typing import Dict
from typing import Optional

from pydantic.dataclasses import dataclass


@dataclass
class State:
    """Health state and performance metrics of a process.

    This class tracks both error states and execution statistics for a process,
    providing a comprehensive view of the process's health and performance.

    Attributes:
        ok: Status of the process. False if an error occurred in the most recent run.
        error: Error message from most recent error, if any.
        error_type: Error type name from most recent error, if any.
        error_time: Timestamp of the most recent error, if any.
        error_count: Total number of errors encountered since process start.
        execution_count: Total number of executions since process start.
        total_duration: Cumulative execution time of all runs.
        max_duration: Longest execution time observed.
        last_duration_warning: When the last warning about long execution was logged.
    """

    # Error tracking
    ok: bool = True
    error: Optional[str] = None
    error_type: Optional[str] = None
    error_time: Optional[float] = None
    error_count: int = 0

    # Execution metrics
    execution_count: int = 0
    total_duration: timedelta = field(default_factory=timedelta)
    max_duration: timedelta = field(default_factory=timedelta)
    last_duration_warning: Optional[datetime] = None

    def asdict(self) -> Dict[str, Any]:
        """Return dict representation of the State object."""
        # NOTE: just construct dict ourselves instead?
        return asdict(self)

    def set_ok(self) -> None:
        """Set current state to OK, clear error information.

        NOTE: Does not reset the error count or execution metrics.
        """
        self.ok = True
        self.error = None
        self.error_type = None
        self.error_time = None

    def set_error(self, exc: Exception) -> None:
        """Set current state to error and record error information.

        Args:
            exc (Exception): The exception that caused the error state.
        """
        self.ok = False
        self.error = str(exc)
        self.error_type = type(exc).__name__
        self.error_time = time.time()
        self.error_count += 1

    def record_execution(self, duration: timedelta) -> None:
        """Record metrics for a process execution.

        Args:
            duration (timedelta): The duration of the execution that just completed.
        """
        self.execution_count += 1
        self.total_duration += duration
        self.max_duration = max(self.max_duration, duration)

    @property
    def avg_duration(self) -> Optional[timedelta]:
        """Calculate average execution duration.

        Returns:
            Optional[timedelta]: Average duration of all executions, or None if no executions recorded.
        """
        if self.execution_count == 0:
            return None
        return self.total_duration / self.execution_count


class Manager(BaseManager):
    pass


class StateProxy(NamespaceProxy):
    # https://stackoverflow.com/a/63741184 (added return in wrapper function)
    # As a one-off, we use a static Proxy type, but if we need to do this
    # to other types as well, it might be worth making a Proxy factory function
    """A proxy class that gives access to all attributes of a State object."""

    _exposed_ = tuple(dir(State))

    def __getattr__(self, name):
        result = super().__getattr__(name)
        if isinstance(result, types.MethodType):

            def wrapper(*args, **kwargs):
                return self._callmethod(name, args, kwargs)

            return wrapper
        return result


class StateManager(BaseManager):
    """Custom subclass of BaseManager with type annotations for custom types."""

    # We need to do this to make mypy happy with calling .State() on the manager class
    # This stub will be overwritten by the actual method created by register()
    def State(self) -> State: ...


StateManager.register("State", State, proxytype=StateProxy)


def get_manager() -> StateManager:
    m = StateManager()
    m.start()
    return m
