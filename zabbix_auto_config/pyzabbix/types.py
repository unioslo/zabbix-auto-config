"""Type definitions for Zabbix API objects.

Since we are supporting multiple versions of the Zabbix API at the same time,
we operate with somewhat lenient model definitions; models change between versions,
and we must ensure that we support them all.

Fields that only apply to subset of versions are marked by a comment
denoting the version they are introduced/removed in.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from typing import Any
from typing import Dict
from typing import List
from typing import MutableMapping
from typing import Optional
from typing import Protocol
from typing import Sequence
from typing import Union

from pydantic import AliasChoices
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import ValidationError
from pydantic import ValidationInfo
from pydantic import ValidatorFunctionWrapHandler
from pydantic import WrapValidator
from pydantic import field_serializer
from pydantic import field_validator
from pydantic_core import PydanticCustomError
from typing_extensions import Annotated
from typing_extensions import Literal
from typing_extensions import TypeAliasType
from typing_extensions import TypedDict

from zabbix_auto_config.pyzabbix.enums import InventoryMode
from zabbix_auto_config.pyzabbix.enums import MonitoringStatus

if TYPE_CHECKING:
    from zabbix_auto_config.pyzabbix.enums import InterfaceType

SortOrder = Literal["ASC", "DESC"]


# Source: https://docs.pydantic.dev/2.7/concepts/types/#named-recursive-types
def json_custom_error_validator(
    value: Any, handler: ValidatorFunctionWrapHandler, _info: ValidationInfo
) -> Any:
    """Simplify the error message to avoid a gross error stemming from
    exhaustive checking of all union options.
    """  # noqa: D205
    try:
        return handler(value)
    except ValidationError:
        raise PydanticCustomError(
            "invalid_json",
            "Input is not valid json",
        ) from None


Json = TypeAliasType(
    "Json",
    Annotated[
        Union[
            MutableMapping[str, "Json"],
            Sequence["Json"],
            str,
            int,
            float,
            bool,
            None,
        ],
        WrapValidator(json_custom_error_validator),
    ],
)


ParamsType = MutableMapping[str, Json]
"""Type used to construct parameters for API requests.
Can only contain native JSON-serializable types.
"""


class ModifyHostItem(TypedDict):
    """Argument for a host ID in an API request."""

    hostid: Union[str, int]


ModifyHostParams = List[ModifyHostItem]

"""A list of host IDs in an API request.

E.g. `[{"hostid": "123"}, {"hostid": "456"}]`
"""


class ModifyGroupItem(TypedDict):
    """Argument for a group ID in an API request."""

    groupid: Union[str, int]


ModifyGroupParams = List[ModifyGroupItem]
"""A list of host/template group IDs in an API request.

E.g. `[{"groupid": "123"}, {"groupid": "456"}]`
"""


class ModifyTemplateItem(TypedDict):
    """Argument for a template ID in an API request."""

    templateid: Union[str, int]


ModifyTemplateParams = List[ModifyTemplateItem]
"""A list of template IDs in an API request.

E.g. `[{"templateid": "123"}, {"templateid": "456"}]`
"""


class CreateUpdateHostInterfaceParams(TypedDict):
    main: bool
    port: str
    type: InterfaceType
    use_ip: bool
    ip: str
    dns: str


class ZabbixAPIError(BaseModel):
    """Zabbix API error information."""

    code: int
    message: str
    data: Optional[str] = None


class ZabbixAPIResponse(BaseModel):
    """The raw response from the Zabbix API"""

    jsonrpc: str
    id: int
    result: Any = None
    """Result of API call, if request succeeded."""
    error: Optional[ZabbixAPIError] = None
    """Error info, if request failed."""


class ZabbixAPIBaseModel(BaseModel):
    """Base model for Zabbix API objects."""

    model_config = ConfigDict(validate_assignment=True, extra="ignore")

    def model_dump_api(self) -> Dict[str, Any]:
        """Dump the model as a JSON-serializable dict used in API calls
        where None values are removed."""
        return self.model_dump(mode="json", exclude_none=True)


class ZabbixRight(ZabbixAPIBaseModel):
    permission: int
    id: str
    name: Optional[str] = None  # name of group (injected by application)

    def model_dump_api(self) -> Dict[str, Any]:
        return self.model_dump(
            mode="json", include={"permission", "id"}, exclude_none=True
        )


class User(ZabbixAPIBaseModel):
    userid: str
    username: str = Field(..., validation_alias=AliasChoices("username", "alias"))
    name: Optional[str] = None
    surname: Optional[str] = None
    url: Optional[str] = None
    autologin: Optional[str] = None
    autologout: Optional[str] = None
    roleid: Optional[int] = Field(
        default=None, validation_alias=AliasChoices("roleid", "type")
    )
    # NOTE: Not adding properties we don't use, since Zabbix has a habit of breaking
    # its own API by changing names and types of properties between versions.


class Usergroup(ZabbixAPIBaseModel):
    name: str
    usrgrpid: str
    gui_access: int
    users_status: int
    rights: List[ZabbixRight] = []
    hostgroup_rights: List[ZabbixRight] = []
    templategroup_rights: List[ZabbixRight] = []
    users: List[User] = []


class Template(ZabbixAPIBaseModel):
    """A template object. Can contain hosts and other templates."""

    templateid: str
    host: str
    hosts: List[Host] = []
    templates: List[Template] = []
    """Child templates (templates inherited from this template)."""

    parent_templates: List[Template] = Field(
        default_factory=list,
        validation_alias=AliasChoices("parentTemplates", "parent_templates"),
        serialization_alias="parentTemplates",  # match JSON output to API format
    )
    """Parent templates (templates this template inherits from)."""

    name: Optional[str] = None
    """The visible name of the template."""


class TemplateGroup(ZabbixAPIBaseModel):
    groupid: str
    name: str
    uuid: str = ""
    templates: List[Template] = []


class HostGroup(ZabbixAPIBaseModel):
    groupid: str
    name: str
    hosts: List[Host] = []
    flags: int = 0
    internal: Optional[int] = None  # <6.2
    templates: List[Template] = []  # <6.2


class HostTag(ZabbixAPIBaseModel):
    tag: str
    value: str
    automatic: Optional[int] = Field(default=None, exclude=True)
    """Tag is automatically set by host discovery. Only used for lookups."""


# TODO: expand Host model with all possible fields
# Add alternative constructor to construct from API result
class Host(ZabbixAPIBaseModel):
    hostid: str
    host: str = ""
    description: Optional[str] = None
    groups: List[HostGroup] = Field(
        default_factory=list,
        # Compat for >= 6.2.0
        validation_alias=AliasChoices("groups", "hostgroups"),
    )
    templates: List[Template] = Field(default_factory=list)
    parent_templates: List[Template] = Field(
        default_factory=list,
        # Accept both casings
        validation_alias=AliasChoices("parentTemplates", "parent_templates"),
    )
    inventory: Dict[str, Any] = Field(default_factory=dict)
    proxyid: Optional[str] = Field(
        None,
        # Compat for <7.0.0
        validation_alias=AliasChoices("proxyid", "proxy_hostid"),
    )
    proxy_address: Optional[str] = None
    maintenance_status: Optional[str] = None
    zabbix_agent: Optional[int] = Field(
        None, validation_alias=AliasChoices("available", "active_available")
    )
    status: Optional[MonitoringStatus] = None
    macros: List[Macro] = Field(default_factory=list)
    interfaces: List[HostInterface] = Field(default_factory=list)
    tags: List[HostTag] = Field(default_factory=list)
    inventory_mode: InventoryMode = InventoryMode.AUTOMATIC

    def __str__(self) -> str:
        return f"{self.host!r} ({self.hostid})"

    @field_validator("inventory", mode="before")
    @classmethod
    def _empty_list_is_empty_dict(cls, v: Any) -> Any:
        """Converts empty list arg to empty dict"""
        # Due to a PHP quirk, an empty associative array
        # is serialized as an array (list) instead of a map
        # while when it's populated it's always a map (dict)
        # Note how the docs state that this is an "object", not an array (list)
        # https://www.zabbix.com/documentation/current/en/manual/api/reference/host/object#host-inventory
        if v == []:
            return {}
        return v


class HostInterface(ZabbixAPIBaseModel):
    type: int
    ip: str
    dns: Optional[str] = None
    port: str
    useip: bool  # this is an int in the API
    main: int
    # SNMP details
    details: Dict[str, Any] = Field(default_factory=dict)
    # Values not required for creation:
    interfaceid: Optional[str] = None
    available: Optional[int] = None
    hostid: Optional[str] = None
    bulk: Optional[int] = None

    @field_validator("details", mode="before")
    @classmethod
    def _empty_list_is_empty_dict(cls, v: Any) -> Any:
        """Converts empty list arg to empty dict"""
        # Due to a PHP quirk, an empty associative array
        # is serialized as an array (list) instead of a map
        # while when it's populated it's always a map (dict)
        # Note how the docs state that this is an "object", not an array (list)
        # https://www.zabbix.com/documentation/current/en/manual/api/reference/hostinterface/object#details
        if v == []:
            return {}
        return v

    @field_serializer("useip", when_used="json")
    def bool_to_int(self, value: bool, _info) -> int:
        return int(value)


class CreateHostInterfaceDetails(ZabbixAPIBaseModel):
    version: int
    bulk: Optional[int] = None
    community: Optional[str] = None
    max_repetitions: Optional[int] = None
    securityname: Optional[str] = None
    securitylevel: Optional[int] = None
    authpassphrase: Optional[str] = None
    privpassphrase: Optional[str] = None
    authprotocol: Optional[int] = None
    privprotocol: Optional[int] = None
    contextname: Optional[str] = None


class UpdateHostInterfaceDetails(ZabbixAPIBaseModel):
    version: Optional[int] = None
    bulk: Optional[int] = None
    community: Optional[str] = None
    max_repetitions: Optional[int] = None
    securityname: Optional[str] = None
    securitylevel: Optional[int] = None
    authpassphrase: Optional[str] = None
    privpassphrase: Optional[str] = None
    authprotocol: Optional[int] = None
    privprotocol: Optional[int] = None
    contextname: Optional[str] = None


class Proxy(ZabbixAPIBaseModel):
    proxyid: str
    name: str = Field(..., validation_alias=AliasChoices("host", "name"))
    hosts: List[Host] = Field(default_factory=list)
    status: Optional[int] = None
    operating_mode: Optional[int] = None
    address: str = Field(
        validation_alias=AliasChoices(
            "address",  # >=7.0.0
            "proxy_address",  # <7.0.0
        )
    )
    compatibility: Optional[int] = None  # >= 7.0
    version: Optional[int] = None  # >= 7.0

    def __hash__(self) -> str:
        return self.proxyid  # kinda hacky, but lets us use it in dicts


class MacroBase(ZabbixAPIBaseModel):
    macro: str
    value: Optional[str] = None  # Optional in case secret value
    type: int
    """Macro type. 0 - text, 1 - secret, 2 - vault secret (>=7.0)"""
    description: str


class Macro(MacroBase):
    """Macro object. Known as 'host macro' in the Zabbix API."""

    hostid: str
    hostmacroid: str
    automatic: Optional[int] = None  # >= 7.0 only. 0 = user, 1 = discovery rule
    hosts: List[Host] = Field(default_factory=list)
    templates: List[Template] = Field(default_factory=list)


class GlobalMacro(MacroBase):
    globalmacroid: str


class Item(ZabbixAPIBaseModel):
    itemid: str
    delay: Optional[str] = None
    hostid: Optional[str] = None
    interfaceid: Optional[str] = None
    key: Optional[str] = Field(
        default=None, validation_alias=AliasChoices("key_", "key")
    )
    name: Optional[str] = None
    type: Optional[int] = None
    url: Optional[str] = None
    value_type: Optional[int] = None
    description: Optional[str] = None
    history: Optional[str] = None
    lastvalue: Optional[str] = None
    hosts: List[Host] = []


class Role(ZabbixAPIBaseModel):
    roleid: str
    name: str
    type: int
    readonly: int  # 0 = read-write, 1 = read-only


class MediaType(ZabbixAPIBaseModel):
    mediatypeid: str
    name: str
    type: int
    description: Optional[str] = None


class UserMedia(ZabbixAPIBaseModel):
    """Media attached to a user object."""

    # https://www.zabbix.com/documentation/current/en/manual/api/reference/user/object#media
    mediatypeid: str
    sendto: str
    active: int = 0  # 0 = enabled, 1 = disabled (YES REALLY!)
    severity: int = 63  # all (1111 in binary - all bits set)
    period: str = "1-7,00:00-24:00"  # 24/7


class TimePeriod(ZabbixAPIBaseModel):
    period: int
    timeperiod_type: int
    start_date: Optional[datetime] = None
    start_time: Optional[int] = None
    every: Optional[int] = None
    dayofweek: Optional[int] = None
    day: Optional[int] = None
    month: Optional[int] = None


class ProblemTag(ZabbixAPIBaseModel):
    tag: str
    operator: Optional[int]
    value: Optional[str]


class Maintenance(ZabbixAPIBaseModel):
    maintenanceid: str
    name: str
    active_since: Optional[datetime] = None
    active_till: Optional[datetime] = None
    description: Optional[str] = None
    maintenance_type: Optional[int] = None
    tags_evaltype: Optional[int] = None
    timeperiods: List[TimePeriod] = []
    tags: List[ProblemTag] = []
    hosts: List[Host] = []
    hostgroups: List[HostGroup] = Field(
        default_factory=list, validation_alias=AliasChoices("groups", "hostgroups")
    )


class Event(ZabbixAPIBaseModel):
    eventid: str
    source: int
    object: int
    objectid: str
    acknowledged: int
    clock: datetime
    name: str
    value: Optional[int] = None  # docs seem to imply this is optional
    severity: int
    # NYI:
    # r_eventid
    # c_eventid
    # cause_eventid
    # correlationid
    # userid
    # suppressed
    # opdata
    # urls


class Trigger(ZabbixAPIBaseModel):
    triggerid: str
    description: Optional[str]
    expression: Optional[str]
    event_name: str
    opdata: str
    comments: str
    error: str
    flags: int
    lastchange: datetime
    priority: int
    state: int
    templateid: Optional[str]
    type: int
    url: str
    url_name: Optional[str] = None  # >6.0
    value: int
    recovery_mode: int
    recovery_expression: str
    correlation_mode: int
    correlation_tag: str
    manual_close: int
    uuid: str
    hosts: List[Host] = []
    # NYI:
    # groups: List[HostGroup] = Field(
    #     default_factory=list, validation_alias=AliasChoices("groups", "hostgroups")
    # )
    # items
    # functions
    # dependencies
    # discoveryRule
    # lastEvent


class Image(ZabbixAPIBaseModel):
    imageid: str
    name: str
    imagetype: int
    # NOTE: Optional so we can fetch an image without its data
    # This lets us get the IDs of all images without keeping the data in memory
    image: Optional[str] = None


class Map(ZabbixAPIBaseModel):
    sysmapid: str
    name: str
    height: int
    width: int
    backgroundid: Optional[str] = None  # will this be an empty string instead?
    # Other fields are omitted. We only use this for export and import.


class ImportRule(BaseModel):  # does not need to inherit from ZabbixAPIBaseModel
    createMissing: bool
    updateExisting: Optional[bool] = None
    deleteMissing: Optional[bool] = None


class ImportRules(ZabbixAPIBaseModel):
    discoveryRules: ImportRule
    graphs: ImportRule
    groups: Optional[ImportRule] = None  # < 6.2
    host_groups: Optional[ImportRule] = None  # >= 6.2
    hosts: ImportRule
    httptests: ImportRule
    images: ImportRule
    items: ImportRule
    maps: ImportRule
    mediaTypes: ImportRule
    template_groups: Optional[ImportRule] = None  # >= 6.2
    templateLinkage: ImportRule
    templates: ImportRule
    templateDashboards: ImportRule
    triggers: ImportRule
    valueMaps: ImportRule
    templateScreens: Optional[ImportRule] = None  # < 6.0
    applications: Optional[ImportRule] = None  # < 6.0
    screens: Optional[ImportRule] = None  # < 6.0

    model_config = ConfigDict(validate_assignment=True)


class ModelWithHosts(Protocol):
    hosts: List[Host]
