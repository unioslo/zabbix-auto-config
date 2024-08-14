from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Any
from typing import Optional

if TYPE_CHECKING:
    from httpx import Response as HTTPResponse

    from zabbix_auto_config.pyzabbix.types import ParamsType
    from zabbix_auto_config.pyzabbix.types import ZabbixAPIResponse


class PyZabbixError(Exception):
    """Base exception class for PyZabbix exceptions."""


class ZabbixAPIException(PyZabbixError):
    # Extracted from pyzabbix, hence *Exception suffix instead of *Error
    """Base exception class for Zabbix API exceptions."""

    def reason(self) -> str:
        return ""


class ZabbixAPIRequestError(ZabbixAPIException):
    """Zabbix API response error."""

    def __init__(
        self,
        *args: Any,
        params: Optional[ParamsType] = None,
        api_response: Optional[ZabbixAPIResponse] = None,
        response: Optional[HTTPResponse] = None,
    ) -> None:
        super().__init__(*args)
        self.params = params
        self.api_response = api_response
        self.response = response

    def reason(self) -> str:
        if self.api_response and self.api_response.error:
            reason = (
                f"({self.api_response.error.code}) {self.api_response.error.message}"
            )
            if self.api_response.error.data:
                reason += f" {self.api_response.error.data}"
        elif self.response and self.response.text:
            reason = self.response.text
        else:
            reason = str(self)
        return reason


class ZabbixAPIResponseParsingError(ZabbixAPIRequestError):
    """Zabbix API request error."""


class ZabbixAPICallError(ZabbixAPIException):
    """Zabbix API request error."""

    def __str__(self) -> str:
        msg = super().__str__()
        if self.__cause__ and isinstance(self.__cause__, ZabbixAPIRequestError):
            msg = f"{msg}: {self.__cause__.reason()}"
        return msg


class ZabbixNotFoundError(ZabbixAPICallError):
    """A Zabbix API resource was not found."""


class ZACException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class SourceCollectorError(ZACException):
    """Exceptions related to host modifiers."""


class SourceCollectorTypeError(SourceCollectorError):
    """Source collector function returned wrong type."""
