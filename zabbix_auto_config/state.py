import time
import types
from dataclasses import asdict
from multiprocessing.managers import BaseManager, NamespaceProxy
from typing import Any, Dict, Optional

from pydantic.dataclasses import dataclass

@dataclass
class State:
    ok: bool = True
    """True if process has not encountered an error in its most recent run."""
    error: Optional[str] = None
    """The error message if `ok` is False."""
    error_type: Optional[str] = None
    """The type of error if `ok` is False."""
    error_count: int = 0
    """The number of errors the process has encountered."""
    error_time: Optional[float] = None
    """The timestamp of the most recent error."""

    def asdict(self) -> Dict[str, Any]:
        """Return dict representation of the State object."""
        return asdict(self)

    def set_ok(self) -> None:
        """Set the current state to OK, clear error information.

        NOTE
        ----
        This does not reset the error count.
        """
        self.ok = True
        self.error = None
        self.error_type = None
        self.error_time = None

    def set_error(self, exc: Exception) -> None:
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


Manager.register("State", State, proxytype=StateProxy)


def get_manager() -> Manager:
    m = Manager()
    m.start()
    return m
