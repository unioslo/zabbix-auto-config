from __future__ import annotations

import time
import types
from dataclasses import asdict
from multiprocessing.managers import BaseManager
from multiprocessing.managers import NamespaceProxy  # type: ignore[attr-defined]
from typing import Any
from typing import Dict
from typing import Optional

from pydantic.dataclasses import dataclass


@dataclass
class State:
    """Health state of a process."""

    ok: bool = True
    """Status of the process. False if an error has occurred in the most recent run."""

    # BELOW: Only applicable if ok is False

    error: Optional[str] = None
    """Error message for most recent error."""

    error_type: Optional[str] = None
    """Error type name for most recent error"""

    error_time: Optional[float] = None
    """Timestamp of the most recent error."""

    error_count: int = 0
    """Number of errors the process has encountered since starting."""

    def asdict(self) -> Dict[str, Any]:
        """Return dict representation of the State object."""
        # NOTE: just construct dict ourselves instead?
        return asdict(self)

    def set_ok(self) -> None:
        """Set current state to OK, clear error information.

        NOTE
        ----
        Does not reset the error count.
        """
        self.ok = True
        self.error = None
        self.error_type = None
        self.error_time = None

    def set_error(self, exc: Exception) -> None:
        """Set current state to error and record error information."""
        self.ok = False
        self.error = str(exc)
        self.error_type = type(exc).__name__
        self.error_time = time.time()
        self.error_count += 1


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
    def State(self) -> State: ...  # type: ignore[empty-body]


StateManager.register("State", State, proxytype=StateProxy)


def get_manager() -> StateManager:
    m = StateManager()
    m.start()
    return m
