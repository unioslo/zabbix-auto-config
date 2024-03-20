from dataclasses import dataclass, field
import datetime
from functools import lru_cache, wraps
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from typing import List  # noqa: F401


@lru_cache()
def get_td(seconds: int) -> datetime.timedelta:
    """Return a datetime.timedelta object for a given number of seconds."""
    return datetime.timedelta(seconds=seconds)


def compare(f):
    @wraps(f)
    def wrapper(self, other):
        if not isinstance(other, Error):
            raise TypeError(
                f"Can't compare {self.__class__.__name__} with {type(other)}"
            )
        return f(self, other)

    return wrapper


@dataclass
class Error:
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    exception: Optional[Exception] = None

    @compare
    def __lt__(self, other: "Error") -> bool:
        return self.timestamp < other.timestamp

    @compare
    def __eq__(self, other: "Error") -> bool:
        return self.timestamp == other.timestamp

    @compare
    def __gt__(self, other: "Error") -> bool:
        return self.timestamp > other.timestamp

    @compare
    def __le__(self, other: "Error") -> bool:
        return self.timestamp <= other.timestamp

    @compare
    def __ge__(self, other: "Error") -> bool:
        return self.timestamp >= other.timestamp

    @compare
    def __ne__(self, other: "Error") -> bool:
        return self.timestamp != other.timestamp


class RollingErrorCounter:
    """A rolling error counter.

    Counts errors in the last `duration` seconds. If the number of errors
    exceeds `tolerance`, the counter is disabled.
    """

    def __init__(self, duration: float, tolerance: int) -> None:
        if duration < 0:
            raise ValueError("duration must be a positive number")
        self.duration = duration

        if tolerance < 0:
            raise ValueError("tolerance must be a positive integer")
        self.tolerance = tolerance

        self.errors = []  # type: List[Error]

    @property
    def last_error(self) -> Optional[Error]:
        """Return the last error."""
        if len(self.errors) == 0:
            return None
        return self.errors[-1]

    def add(self, exception: Optional[Exception] = None) -> None:
        """Add an error to the counter."""
        self.errors.append(Error(exception=exception))

    def reset(self) -> None:
        """Reset the counter."""
        self.errors.clear()

    def count(self) -> int:
        """Return number of errors in the last duration seconds."""
        while len(self.errors) > 0 and (
            self.errors[0].timestamp < datetime.datetime.now() - get_td(self.duration)
        ):
            self.errors.pop(0)

        return len(self.errors)

    def tolerance_exceeded(self) -> bool:
        """Return True if counter has exceeded tolerance."""
        return self.count() > self.tolerance
