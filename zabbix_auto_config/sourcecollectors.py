from __future__ import annotations

import inspect
import os
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import ValidationError
from typing_extensions import Self

from zabbix_auto_config.exceptions import ZACException


def _get_collector_name(cls: type) -> str:
    """Get the name of a source collector module, falling back on the class name."""
    if hasattr(cls, "__collector_name__") and cls.__collector_name__:
        return str(cls.__collector_name__)
    if module := inspect.getmodule(cls):
        if module.__name__ == "__main__":
            # When run as a script, get the filename without extension
            module_path = inspect.getfile(cls)
            return os.path.splitext(os.path.basename(module_path))[0]
        else:
            # When imported, use the module name
            return module.__name__.split(".")[-1]
    return cls.__name__


class CollectorConfig(BaseModel):
    """Base class for source collector configuration."""

    __collector_name__: str = ""

    model_config = ConfigDict(extra="allow")

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self.__collector_name__ = _get_collector_name(self.__class__)

    @classmethod
    def from_kwargs(cls, **kwargs: Any) -> Self:
        try:
            return cls.model_validate(kwargs)
        except ValidationError as e:
            raise ZACException(
                f"Invalid configuration for source collector {_get_collector_name(cls)!r}: {e}"
            ) from None
