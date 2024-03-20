from __future__ import annotations


class ZACException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class SourceCollectorError(ZACException):
    """Exceptions related to host modifiers."""


class SourceCollectorTypeError(SourceCollectorError):
    """Source collector function returned wrong type."""
