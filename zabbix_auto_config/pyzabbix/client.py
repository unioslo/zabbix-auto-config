#
# The code in this file is based on the pyzabbix library:
# https://github.com/lukecyca/pyzabbix
#
# Numerous changes have been made to the original code to make it more
# type-safe and to better fit the use-cases of the zabbix-cli project.
#
# We have modified the login method to be able to send an auth-token so
# we do not have to login again as long as the auth-token used is still
# active.
#
# We have also modified the output when an error happens to not show
# the username + password information.
#
from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING
from typing import Any
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional
from typing import Union
from typing import cast

import httpx
from pydantic import ValidationError

from zabbix_auto_config.exceptions import ZabbixAPICallError
from zabbix_auto_config.exceptions import ZabbixAPIException
from zabbix_auto_config.exceptions import ZabbixAPIRequestError
from zabbix_auto_config.exceptions import ZabbixAPIResponseParsingError
from zabbix_auto_config.exceptions import ZabbixNotFoundError
from zabbix_auto_config.pyzabbix import compat
from zabbix_auto_config.pyzabbix.enums import AgentAvailable
from zabbix_auto_config.pyzabbix.enums import DataCollectionMode
from zabbix_auto_config.pyzabbix.enums import GUIAccess
from zabbix_auto_config.pyzabbix.enums import InterfaceType
from zabbix_auto_config.pyzabbix.enums import InventoryMode
from zabbix_auto_config.pyzabbix.enums import MaintenanceStatus
from zabbix_auto_config.pyzabbix.enums import MonitoringStatus
from zabbix_auto_config.pyzabbix.enums import TriggerPriority
from zabbix_auto_config.pyzabbix.enums import UsergroupPermission
from zabbix_auto_config.pyzabbix.enums import UserRole
from zabbix_auto_config.pyzabbix.types import CreateHostInterfaceDetails
from zabbix_auto_config.pyzabbix.types import GlobalMacro
from zabbix_auto_config.pyzabbix.types import Host
from zabbix_auto_config.pyzabbix.types import HostGroup
from zabbix_auto_config.pyzabbix.types import HostInterface
from zabbix_auto_config.pyzabbix.types import HostTag
from zabbix_auto_config.pyzabbix.types import Image
from zabbix_auto_config.pyzabbix.types import ImportRules
from zabbix_auto_config.pyzabbix.types import Item
from zabbix_auto_config.pyzabbix.types import Macro
from zabbix_auto_config.pyzabbix.types import Maintenance
from zabbix_auto_config.pyzabbix.types import Map
from zabbix_auto_config.pyzabbix.types import MediaType
from zabbix_auto_config.pyzabbix.types import Proxy
from zabbix_auto_config.pyzabbix.types import Role
from zabbix_auto_config.pyzabbix.types import Template
from zabbix_auto_config.pyzabbix.types import TemplateGroup
from zabbix_auto_config.pyzabbix.types import Trigger
from zabbix_auto_config.pyzabbix.types import UpdateHostInterfaceDetails
from zabbix_auto_config.pyzabbix.types import User
from zabbix_auto_config.pyzabbix.types import Usergroup
from zabbix_auto_config.pyzabbix.types import UserMedia
from zabbix_auto_config.pyzabbix.types import ZabbixAPIResponse
from zabbix_auto_config.pyzabbix.types import ZabbixRight

if TYPE_CHECKING:
    from httpx._types import TimeoutTypes
    from packaging.version import Version
    from typing_extensions import TypedDict

    from zabbix_auto_config.pyzabbix.types import ModifyGroupParams  # noqa: F401
    from zabbix_auto_config.pyzabbix.types import ModifyHostParams  # noqa: F401
    from zabbix_auto_config.pyzabbix.types import ModifyTemplateParams  # noqa: F401
    from zabbix_auto_config.pyzabbix.types import ParamsType  # noqa: F401
    from zabbix_auto_config.pyzabbix.types import SortOrder  # noqa: F401

    class HTTPXClientKwargs(TypedDict, total=False):
        timeout: TimeoutTypes


logger = logging.getLogger(__name__)

RPC_ENDPOINT = "/api_jsonrpc.php"


class ZabbixAPI:
    def __init__(
        self,
        server: str = "http://localhost/zabbix",
        timeout: Optional[int] = None,
    ):
        """Parameters:
        server: Base URI for zabbix web interface (omitting /api_jsonrpc.php)
        session: optional pre-configured requests.Session instance
        timeout: optional connect and read timeout in seconds.
        """
        self.timeout = timeout if timeout else None

        kwargs: HTTPXClientKwargs = {}
        if timeout is not None:
            kwargs["timeout"] = timeout
        self.session = httpx.Client(
            verify=True,
            # Default headers for all requests
            headers={
                "Content-Type": "application/json-rpc",
                "User-Agent": "python/pyzabbix",
                "Cache-Control": "no-cache",
            },
            **kwargs,
        )
        self.auth = ""
        self.id = 0

        server, _, _ = server.partition(RPC_ENDPOINT)
        self.url = f"{server}/api_jsonrpc.php"
        logger.info("JSON-RPC Server Endpoint: %s", self.url)

        # Attributes for properties
        self._version: Optional[Version] = None

    def login(
        self,
        user: Optional[str] = None,
        password: Optional[str] = None,
        auth_token: Optional[str] = None,
    ) -> str:
        """Convenience method for logging into the API and storing the resulting
        auth token as an instance variable.
        """
        # Before we do anything, we try to fetch the API version
        # Without an API connection, we cannot determine
        # the user parameter name to use when logging in.
        try:
            self.version  # property
        except ZabbixAPIRequestError as e:
            raise ZabbixAPIException(
                f"Failed to connect to Zabbix API at {self.url}"
            ) from e

        # The username kwarg was called "user" in Zabbix 5.2 and earlier.
        # This sets the correct kwarg for the version of Zabbix we're using.
        user_kwarg = {compat.login_user_name(self.version): user}

        self.auth = ""  # clear auth before trying to (re-)login

        if not auth_token:
            try:
                auth = self.user.login(**user_kwarg, password=password)
            except Exception as e:
                raise ZabbixAPIRequestError(
                    f"Failed to log in to Zabbix API: {e}"
                ) from e
        else:
            auth = auth_token
            # TODO: confirm we are logged in here
            # self.api_version()  # NOTE: useless? can we remove this?
        self.auth = str(auth) if auth else ""  # ensure str
        return self.auth

    def confimport(self, format: str, source: str, rules: ImportRules) -> Any:
        """Alias for configuration.import because it clashes with
        Python's import reserved keyword
        """
        return self.do_request(
            method="configuration.import",
            params={
                "format": format,
                "source": source,
                "rules": rules.model_dump_api(),
            },
        ).result

    # TODO (pederhan): Use functools.cachedproperty when we drop 3.7 support
    @property
    def version(self) -> Version:
        """Alternate version of api_version() that caches version info
        as a Version object.
        """
        if self._version is None:
            from packaging.version import Version

            self._version = Version(self.apiinfo.version())
        return self._version

    def api_version(self):
        return self.apiinfo.version()

    def do_request(
        self, method: str, params: Optional[ParamsType] = None
    ) -> ZabbixAPIResponse:
        request_json = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.id,
        }

        # We don't have to pass the auth token if asking for the apiinfo.version
        if self.auth and method != "apiinfo.version":
            request_json["auth"] = self.auth
        # TODO: ensure we have auth token if method requires it

        logger.debug("Sending %s to %s", method, self.url)

        try:
            response = self.session.post(self.url, json=request_json)
        except Exception as e:
            raise ZabbixAPIRequestError(
                f"Failed to send request to {self.url} ({method}) with params {params}",
                params=params,
            ) from e

        logger.debug("Response Code: %s", str(response.status_code))

        # NOTE: Getting a 412 response code means the headers are not in the
        # list of allowed headers.
        # OR we didnt pass an auth token
        response.raise_for_status()

        if not len(response.text):
            raise ZabbixAPIRequestError("Received empty response", response=response)

        self.id += 1

        try:
            resp = ZabbixAPIResponse.model_validate_json(response.text)
        except ValidationError as e:
            raise ZabbixAPIResponseParsingError(
                "Zabbix API returned malformed response", response=response
            ) from e
        except ValueError as e:
            raise ZabbixAPIResponseParsingError(
                "Zabbix API returned invalid JSON", response=response
            ) from e

        if resp.error is not None:
            # some errors don't contain 'data': workaround for ZBX-9340
            if not resp.error.data:
                resp.error.data = "No data"
            raise ZabbixAPIRequestError(
                f"Error: {resp.error.message}",
                api_response=resp,
                response=response,
            )
        return resp

    def get_hostgroup(
        self,
        name_or_id: str,
        search: bool = False,
        select_hosts: bool = False,
        select_templates: bool = False,
        sort_order: Optional[SortOrder] = None,
        sort_field: Optional[str] = None,
    ) -> HostGroup:
        """Fetches a host group given its name or ID.

        Name or ID argument is interpeted as an ID if the argument is numeric.

        Uses filtering by default, but can be switched to searching by setting
        the `search` argument to True.

        Args:
            name_or_id (str): Name or ID of the host group.
            search (bool, optional): Search for host groups using the given pattern instead of filtering. Defaults to False.
            select_hosts (bool, optional): Fetch hosts in host groups. Defaults to False.
            select_templates (bool, optional): <6.2 ONLY: Fetch templates in host groups. Defaults to False.

        Raises:
            ZabbixNotFoundError: Group is not found.

        Returns:
            HostGroup: The host group object.
        """
        hostgroups = self.get_hostgroups(
            name_or_id,
            search=search,
            sort_order=sort_order,
            sort_field=sort_field,
            select_hosts=select_hosts,
            select_templates=select_templates,
        )
        if not hostgroups:
            raise ZabbixNotFoundError(f"Host group {name_or_id!r} not found")
        return hostgroups[0]

    def get_hostgroups(
        self,
        *names_or_ids: str,
        search: bool = False,
        search_union: bool = True,
        select_hosts: bool = False,
        select_templates: bool = False,
        sort_order: Optional[SortOrder] = None,
        sort_field: Optional[str] = None,
    ) -> List[HostGroup]:
        """Fetches a list of host groups given its name or ID.

        Name or ID argument is interpeted as an ID if the argument is numeric.

        Uses filtering by default, but can be switched to searching by setting
        the `search` argument to True.

        Args:
            name_or_id (str): Name or ID of the host group.
            search (bool, optional): Search for host groups using the given pattern instead of filtering. Defaults to False.
            search_union (bool, optional): Union searching. Has no effect if `search` is False. Defaults to True.
            select_hosts (bool, optional): Fetch hosts in host groups. Defaults to False.
            select_templates (bool, optional): <6.2 ONLY: Fetch templates in host groups. Defaults to False.
            sort_order (SortOrder, optional): Sort order. Defaults to None.
            sort_field (str, optional): Sort field. Defaults to None.

        Raises:
            ZabbixNotFoundError: Group is not found.

        Returns:
            List[HostGroup]: List of host groups.
        """
        # TODO: refactor this along with other methods that take names or ids (or wildcards)
        params: ParamsType = {"output": "extend"}

        if "*" in names_or_ids:
            names_or_ids = tuple()

        if names_or_ids:
            for name_or_id in names_or_ids:
                norid = name_or_id.strip()
                is_id = norid.isnumeric()
                norid_key = "groupid" if is_id else "name"
                if search and not is_id:
                    params["searchWildcardsEnabled"] = True
                    params["searchByAny"] = search_union
                    params.setdefault("search", {}).setdefault("name", []).append(
                        name_or_id
                    )
                else:
                    params["filter"] = {norid_key: name_or_id}
        if select_hosts:
            params["selectHosts"] = "extend"
        if self.version.release < (6, 2, 0) and select_templates:
            params["selectTemplates"] = "extend"
        if sort_order:
            params["sortorder"] = sort_order
        if sort_field:
            params["sortfield"] = sort_field

        resp: List[Any] = self.hostgroup.get(**params) or []
        return [HostGroup(**hostgroup) for hostgroup in resp]

    def create_hostgroup(self, name: str) -> str:
        """Creates a host group with the given name."""
        try:
            resp = self.hostgroup.create(name=name)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(f"Failed to create host group {name!r}") from e
        if not resp or not resp.get("groupids"):
            raise ZabbixAPICallError(
                "Host group creation returned no data. Unable to determine if group was created."
            )
        return str(resp["groupids"][0])

    def delete_hostgroup(self, hostgroup_id: str) -> None:
        """Deletes a host group given its ID."""
        try:
            self.hostgroup.delete(hostgroup_id)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to delete host group(s) with ID {hostgroup_id}"
            ) from e

    def add_hosts_to_hostgroups(
        self, hosts: List[Host], hostgroups: List[HostGroup]
    ) -> None:
        """Adds hosts to one or more host groups."""
        try:
            self.hostgroup.massadd(
                groups=[{"groupid": hg.groupid} for hg in hostgroups],
                hosts=[{"hostid": host.hostid} for host in hosts],
            )
        except ZabbixAPIException as e:
            hgs = ", ".join(hg.name for hg in hostgroups)
            raise ZabbixAPICallError(f"Failed to add hosts to {hgs}") from e

    def remove_hosts_from_hostgroups(
        self, hosts: List[Host], hostgroups: List[HostGroup]
    ) -> None:
        """Removes the given hosts from one or more host groups."""
        try:
            self.hostgroup.massremove(
                groupids=[hg.groupid for hg in hostgroups],
                hostids=[host.hostid for host in hosts],
            )
        except ZabbixAPIException as e:
            hgs = ", ".join(hg.name for hg in hostgroups)
            raise ZabbixAPICallError(f"Failed to remove hosts from {hgs}") from e

    def get_templategroup(
        self,
        name_or_id: str,
        search: bool = False,
        select_templates: bool = False,
    ) -> TemplateGroup:
        """Fetches a template group given its name or ID.

        Name or ID argument is interpeted as an ID if the argument is numeric.

        Uses filtering by default, but can be switched to searching by setting
        the `search` argument to True.

        Args:
            name_or_id (str): Name or ID of the template group.
            search (bool, optional): Search for template groups using the given pattern instead of filtering. Defaults to False.
            select_templates (bool, optional): Fetch full information for each template in the group. Defaults to False.

        Raises:
            ZabbixNotFoundError: Group is not found.

        Returns:
            TemplateGroup: The template group object.
        """
        tgroups = self.get_templategroups(
            name_or_id, search=search, select_templates=select_templates
        )
        if not tgroups:
            raise ZabbixNotFoundError(f"Template group {name_or_id!r} not found")
        return tgroups[0]

    def get_templategroups(
        self,
        *names_or_ids: str,
        search: bool = False,
        search_union: bool = True,
        select_templates: bool = False,
        sort_field: Optional[str] = None,
        sort_order: Optional[SortOrder] = None,
    ) -> List[TemplateGroup]:
        """Fetches a list of template groups, optionally filtered by name(s).

        Name or ID argument is interpeted as an ID if the argument is numeric.

        Uses filtering by default, but can be switched to searching by setting
        the `search` argument to True.

        Args:
            name_or_id (str): Name or ID of the template group.
            search (bool, optional): Search for template groups using the given pattern instead of filtering. Defaults to False.
            search_union (bool, optional): Union searching. Has no effect if `search` is False. Defaults to True.
            select_templates (bool, optional): Fetch templates in each group. Defaults to False.
            sort_order (SortOrder, optional): Sort order. Defaults to None.
            sort_field (str, optional): Sort field. Defaults to None.

        Raises:
            ZabbixNotFoundError: Group is not found.

        Returns:
            List[TemplateGroup]: List of template groups.
        """
        # FIXME: ensure we use searching correctly here
        # TODO: refactor this along with other methods that take names or ids (or wildcards)
        params: ParamsType = {"output": "extend"}

        if "*" in names_or_ids:
            names_or_ids = tuple()

        if names_or_ids:
            for name_or_id in names_or_ids:
                norid = name_or_id.strip()
                is_id = norid.isnumeric()
                norid_key = "groupid" if is_id else "name"
                if search and not is_id:
                    params["searchWildcardsEnabled"] = True
                    params["searchByAny"] = search_union
                    params.setdefault("search", {}).setdefault("name", []).append(
                        name_or_id
                    )
                else:
                    params["filter"] = {norid_key: name_or_id}

        if select_templates:
            params["selectTemplates"] = "extend"
        if sort_order:
            params["sortorder"] = sort_order
        if sort_field:
            params["sortfield"] = sort_field

        try:
            resp: List[Any] = self.templategroup.get(**params) or []
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to fetch template groups") from e
        return [TemplateGroup(**tgroup) for tgroup in resp]

    def create_templategroup(self, name: str) -> str:
        """Creates a template group with the given name."""
        try:
            resp = self.templategroup.create(name=name)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(f"Failed to create template group {name!r}") from e
        if not resp or not resp.get("groupids"):
            raise ZabbixAPICallError(
                "Template group creation returned no data. Unable to determine if group was created."
            )
        return str(resp["groupids"][0])

    def delete_templategroup(self, templategroup_id: str) -> None:
        """Deletes a template group given its ID."""
        try:
            self.templategroup.delete(templategroup_id)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to delete template group(s) with ID {templategroup_id}"
            ) from e

    def get_host(
        self,
        name_or_id: str,
        select_groups: bool = False,
        select_templates: bool = False,
        select_interfaces: bool = False,
        select_inventory: bool = False,
        select_macros: bool = False,
        proxyid: Optional[str] = None,
        maintenance: Optional[MaintenanceStatus] = None,
        status: Optional[MonitoringStatus] = None,
        agent_status: Optional[AgentAvailable] = None,
        sort_field: Optional[str] = None,
        sort_order: Optional[SortOrder] = None,
        search: bool = False,
    ) -> Host:
        """Fetches a host given a name or id."""
        hosts = self.get_hosts(
            name_or_id,
            select_groups=select_groups,
            select_templates=select_templates,
            select_inventory=select_inventory,
            select_interfaces=select_interfaces,
            select_macros=select_macros,
            proxyid=proxyid,
            sort_field=sort_field,
            sort_order=sort_order,
            search=search,
            maintenance=maintenance,
            status=status,
            agent_status=agent_status,
        )
        if not hosts:
            raise ZabbixNotFoundError(
                f"Host {name_or_id!r} not found. Check your search pattern and filters."
            )
        return hosts[0]

    def get_hosts(
        self,
        *names_or_ids: str,
        select_groups: bool = False,
        select_templates: bool = False,
        select_inventory: bool = False,
        select_macros: bool = False,
        select_interfaces: bool = False,
        select_tags: bool = False,
        proxyid: Optional[str] = None,
        # These params take special API values we don't want to evaluate
        # inside this method, so we delegate it to the enums.
        maintenance: Optional[MaintenanceStatus] = None,
        status: Optional[MonitoringStatus] = None,
        agent_status: Optional[AgentAvailable] = None,
        flags: Optional[int] = None,
        sort_field: Optional[str] = None,
        sort_order: Optional[Literal["ASC", "DESC"]] = None,
        search: Optional[
            bool
        ] = True,  # we generally always want to search when multiple hosts are requested
        # **filter_kwargs,
    ) -> List[Host]:
        """Fetches all hosts matching the given criteria(s).

        Hosts can be filtered by name or ID. Names and IDs cannot be mixed.
        If no criteria are given, all hosts are returned.

        A number of extra properties can be fetched for each host by setting
        the corresponding `select_*` argument to `True`. Each Host object
        will have the corresponding property populated.


        If `search=True`, only a single hostname pattern should be given;
        criterias are matched using logical AND (narrows down results).
        If `search=False`, multiple hostnames or IDs can be used.

        Args:
            select_groups (bool, optional): Include host (& template groups if >=6.2). Defaults to False.
            select_templates (bool, optional): Include templates. Defaults to False.
            select_inventory (bool, optional): Include inventory items. Defaults to False.
            select_macros (bool, optional): Include host macros. Defaults to False.
            proxyid (Optional[str], optional): Filter by proxy ID. Defaults to None.
            maintenance (Optional[MaintenanceStatus], optional): Filter by maintenance status. Defaults to None.
            status (Optional[MonitoringStatus], optional): Filter by monitoring status. Defaults to None.
            agent_status (Optional[AgentAvailable], optional): Filter by agent availability. Defaults to None.
            sort_field (Optional[str], optional): Sort hosts by the given field. Defaults to None.
            sort_order (Optional[Literal[ASC, DESC]], optional): Sort order. Defaults to None.
            search (Optional[bool], optional): Force positional arguments to be treated as a search pattern. Defaults to True.

        Raises:
            ZabbixAPIException: _description_

        Returns:
            List[Host]: _description_
        """
        params: ParamsType = {"output": "extend"}
        filter_params: ParamsType = {}

        # Filter by the given host name or ID if we have one
        if names_or_ids:
            id_mode: Optional[bool] = None
            for name_or_id in names_or_ids:
                name_or_id = name_or_id.strip()
                is_id = name_or_id.isnumeric()
                if search is None:  # determine if we should search
                    search = not is_id

                # Set ID mode if we haven't already
                # and ensure we aren't mixing IDs and names
                if id_mode is None:
                    id_mode = is_id
                else:
                    if id_mode != is_id:
                        raise ZabbixAPICallError("Cannot mix host names and IDs.")

                # Searching for IDs is pointless - never allow it
                # Logical AND for multiple unique identifiers is not possible
                if search and not is_id:
                    params["searchWildcardsEnabled"] = True
                    params["searchByAny"] = True
                    params.setdefault("search", {}).setdefault("host", []).append(
                        name_or_id
                    )
                elif is_id:
                    params.setdefault("hostids", []).append(name_or_id)
                else:
                    filter_params.setdefault("host", []).append(name_or_id)

        # Filters are applied with a logical AND (narrows down)
        if proxyid:
            filter_params[compat.host_proxyid(self.version)] = proxyid
        if maintenance is not None:
            filter_params["maintenance_status"] = maintenance
        if status is not None:
            filter_params["status"] = status
        if agent_status is not None:
            filter_params[compat.host_available(self.version)] = agent_status
        if flags is not None:
            filter_params["flags"] = flags

        if filter_params:  # Only add filter if we actually have filter params
            params["filter"] = filter_params

        if select_groups:
            # still returns the result under the "groups" property
            # even if we use the new 6.2 selectHostGroups param
            param = compat.param_host_get_groups(self.version)
            params[param] = "extend"
        if select_templates:
            params["selectParentTemplates"] = "extend"
        if select_inventory:
            params["selectInventory"] = "extend"
        if select_macros:
            params["selectMacros"] = "extend"
        if select_interfaces:
            params["selectInterfaces"] = "extend"
        if select_tags:
            params["selectTags"] = "extend"
        if sort_field:
            params["sortfield"] = sort_field
        if sort_order:
            params["sortorder"] = sort_order

        resp: List[Any] = self.host.get(**params) or []
        # TODO add result to cache
        return [Host(**resp) for resp in resp]

    def create_host(
        self,
        host: str,
        groups: List[HostGroup],
        proxy: Optional[Proxy] = None,
        status: MonitoringStatus = MonitoringStatus.ON,
        interfaces: Optional[List[HostInterface]] = None,
        inventory_mode: InventoryMode = InventoryMode.AUTOMATIC,
        inventory: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
    ) -> str:
        params: ParamsType = {
            "host": host,
            "status": status,
            "inventory_mode": inventory_mode,
        }

        # dedup group IDs
        groupids = list({group.groupid for group in groups})
        params["groups"] = [{"groupid": groupid} for groupid in groupids]

        if proxy:
            params[compat.host_proxyid(self.version)] = proxy.proxyid

        if interfaces:
            params["interfaces"] = [iface.model_dump_api() for iface in interfaces]

        if inventory:
            params["inventory"] = inventory

        if description:
            params["description"] = description

        try:
            resp = self.host.create(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(f"Failed to create host {host!r}") from e
        if not resp or not resp.get("hostids"):
            raise ZabbixAPICallError(
                "Host creation returned no data. Unable to determine if host was created."
            )
        return str(resp["hostids"][0])

    def update_host(
        self,
        host: Host,
        status: Optional[MonitoringStatus] = None,
        groups: Optional[List[HostGroup]] = None,
        templates: Optional[List[Template]] = None,
        tags: Optional[List[HostTag]] = None,
        inventory_mode: Optional[InventoryMode] = None,
    ) -> None:
        """Update a host.

        Parameters
        ----------
        host : Host
            The host to update
        status : Optional[MonitoringStatus]
            New stauts for the host
        groups : Optional[List[HostGroup]]
            New host groups for the host. Replaces existing groups.
        templates: Optional[List[Template]]
            New templates for the host. Replaces existing templates.
        """
        params: ParamsType = {"hostid": host.hostid}
        if groups is not None:
            params["groups"] = [{"groupid": hg.groupid} for hg in groups]
        if status is not None:
            params["status"] = status
        if templates is not None:
            params["templates"] = templates
        if tags is not None:
            params["tags"] = tags
        if inventory_mode is not None:
            params["inventory_mode"] = inventory_mode
        try:
            self.host.update(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update host {host.host} ({host.hostid}): {e}"
            )

    def delete_host(self, host_id: str) -> None:
        """Deletes a host."""
        try:
            self.host.delete(host_id)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to delete host with ID {host_id!r}"
            ) from e

    def host_exists(self, name_or_id: str) -> bool:
        """Checks if a host exists given its name or ID."""
        try:
            self.get_host(name_or_id)
        except ZabbixNotFoundError:
            return False
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Unknown error when fetching host {name_or_id}"
            ) from e
        else:
            return True

    def hostgroup_exists(self, hostgroup_name: str) -> bool:
        try:
            self.get_hostgroup(hostgroup_name)
        except ZabbixNotFoundError:
            return False
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to fetch host group {hostgroup_name}"
            ) from e
        else:
            return True

    def get_host_interface(
        self,
        interfaceid: Optional[str] = None,
    ) -> HostInterface:
        """Fetches a host interface given its ID"""
        interfaces = self.get_host_interfaces(interfaceids=interfaceid)
        if not interfaces:
            raise ZabbixNotFoundError(f"Host interface with ID {interfaceid} not found")
        return interfaces[0]

    def get_host_interfaces(
        self,
        hostids: Union[str, List[str], None] = None,
        interfaceids: Union[str, List[str], None] = None,
        itemids: Union[str, List[str], None] = None,
        triggerids: Union[str, List[str], None] = None,
        # Can expand with the rest of the parameters if needed
    ) -> List[HostInterface]:
        """Fetches a list of host interfaces, optionally filtered by host ID,
        interface ID, item ID or trigger ID.
        """
        params: ParamsType = {"output": "extend"}
        if hostids:
            params["hostids"] = hostids
        if interfaceids:
            params["interfaceids"] = interfaceids
        if itemids:
            params["itemids"] = itemids
        if triggerids:
            params["triggerids"] = triggerids
        try:
            resp = self.hostinterface.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to fetch host interfaces") from e
        return [HostInterface(**iface) for iface in resp]

    def create_host_interface(
        self,
        host: Host,
        main: bool,
        type: InterfaceType,
        use_ip: bool,
        port: str,
        ip: Optional[str] = None,
        dns: Optional[str] = None,
        details: Optional[CreateHostInterfaceDetails] = None,
    ) -> str:
        if not ip and not dns:
            raise ZabbixAPIException("Either IP or DNS must be provided")
        if use_ip and not ip:
            raise ZabbixAPIException("IP must be provided if using IP connection mode.")
        if not use_ip and not dns:
            raise ZabbixAPIException(
                "DNS must be provided if using DNS connection mode."
            )
        params: ParamsType = {
            "hostid": host.hostid,
            "main": int(main),
            "type": type,
            "useip": int(use_ip),
            "port": str(port),
            "ip": ip or "",
            "dns": dns or "",
        }
        if type == InterfaceType.SNMP:
            if not details:
                raise ZabbixAPIException(
                    "SNMP details must be provided for SNMP interfaces."
                )
            params["details"] = details.model_dump_api()

        try:
            resp = self.hostinterface.create(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to create host interface for host {host.host!r}"
            ) from e
        if not resp or not resp.get("interfaceids"):
            raise ZabbixAPICallError(
                "Host interface creation returned no data. Unable to determine if interface was created."
            )
        return str(resp["interfaceids"][0])

    def update_host_interface(
        self,
        interface: HostInterface,
        hostid: Optional[str] = None,
        main: Optional[bool] = None,
        type: Optional[InterfaceType] = None,
        use_ip: Optional[bool] = None,
        port: Optional[str] = None,
        ip: Optional[str] = None,
        dns: Optional[str] = None,
        details: Optional[UpdateHostInterfaceDetails] = None,
    ) -> None:
        params: ParamsType = {"interfaceid": interface.interfaceid}
        if hostid is not None:
            params["hostid"] = hostid
        if main is not None:
            params["main"] = int(main)
        if type is not None:
            params["type"] = type
        if use_ip is not None:
            params["useip"] = int(use_ip)
        if port is not None:
            params["port"] = str(port)
        if ip is not None:
            params["ip"] = ip
        if dns is not None:
            params["dns"] = dns
        if details is not None:
            params["details"] = details.model_dump_api()
        try:
            self.hostinterface.update(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update host interface with ID {interface.interfaceid}"
            ) from e

    def delete_host_interface(self, interface_id: str) -> None:
        """Deletes a host interface."""
        try:
            self.hostinterface.delete(interface_id)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to delete host interface with ID {interface_id}"
            ) from e

    def get_usergroup(
        self,
        name: str,
        select_users: bool = False,
        select_rights: bool = False,
        search: bool = False,
    ) -> Usergroup:
        """Fetches a user group by name. Always fetches the full contents of the group."""
        groups = self.get_usergroups(
            name,
            select_users=select_users,
            select_rights=select_rights,
            search=search,
        )
        if not groups:
            raise ZabbixNotFoundError(f"User group {name!r} not found")
        return groups[0]

    def get_usergroups(
        self,
        *names: str,
        # See get_usergroup for why these are set to True by default
        select_users: bool = True,
        select_rights: bool = True,
        search: bool = False,
    ) -> List[Usergroup]:
        """Fetches all user groups. Optionally includes users and rights."""
        params: ParamsType = {
            "output": "extend",
        }
        if "*" in names:
            names = tuple()
        if search:
            params["searchByAny"] = True  # Union search (default is intersection)
            params["searchWildcardsEnabled"] = True

        if names:
            for name in names:
                name = name.strip()
                if search:
                    params.setdefault("search", {}).setdefault("name", []).append(name)
                else:
                    params["filter"] = {"name": name}

        # Rights were split into host and template group rights in 6.2.0
        if select_rights:
            if self.version.release >= (6, 2, 0):
                params["selectHostGroupRights"] = "extend"
                params["selectTemplateGroupRights"] = "extend"
            else:
                params["selectRights"] = "extend"
        if select_users:
            params["selectUsers"] = "extend"

        try:
            res = self.usergroup.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Unable to fetch user groups") from e
        else:
            return [Usergroup(**usergroup) for usergroup in res]

    def create_usergroup(
        self,
        usergroup_name: str,
        disabled: bool = False,
        gui_access: GUIAccess = GUIAccess.DEFAULT,
    ) -> str:
        """Creates a user group with the given name."""
        try:
            resp = self.usergroup.create(
                name=usergroup_name,
                users_status=int(disabled),
                gui_access=gui_access,
            )
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to create user group {usergroup_name!r}"
            ) from e
        if not resp or not resp.get("usrgrpids"):
            raise ZabbixAPICallError(
                "User group creation returned no data. Unable to determine if group was created."
            )
        return str(resp["usrgrpids"][0])

    def add_usergroup_users(self, usergroup_name: str, users: List[User]) -> None:
        """Add users to a user group. Ignores users already in the group."""
        self._update_usergroup_users(usergroup_name, users, remove=False)

    def remove_usergroup_users(self, usergroup_name: str, users: List[User]) -> None:
        """Remove users from a user group. Ignores users not in the group."""
        self._update_usergroup_users(usergroup_name, users, remove=True)

    def _update_usergroup_users(
        self, usergroup_name: str, users: List[User], remove: bool = False
    ) -> None:
        """Add/remove users from user group.

        Takes in the name of a user group instead of a `UserGroup` object
        to ensure the user group is fetched with `select_users=True`.
        """
        usergroup = self.get_usergroup(usergroup_name, select_users=True)

        params: ParamsType = {"usrgrpid": usergroup.usrgrpid}

        # Add new IDs to existing and remove duplicates
        current_userids = [user.userid for user in usergroup.users]
        ids_update = [user.userid for user in users if user.userid]
        if remove:
            new_userids = list(set(current_userids) - set(ids_update))
        else:
            new_userids = list(set(current_userids + ids_update))

        if self.version.release >= (6, 0, 0):
            params["users"] = {"userid": uid for uid in new_userids}
        else:
            params["userids"] = new_userids
        self.usergroup.update(usrgrpid=usergroup.usrgrpid, userids=new_userids)

    def update_usergroup_rights(
        self,
        usergroup_name: str,
        groups: List[str],
        permission: UsergroupPermission,
        hostgroup: bool,
    ) -> None:
        """Update usergroup rights for host or template groups."""
        usergroup = self.get_usergroup(usergroup_name, select_rights=True)

        params: ParamsType = {"usrgrpid": usergroup.usrgrpid}

        if hostgroup:
            hostgroups = [self.get_hostgroup(hg) for hg in groups]
            if self.version.release >= (6, 2, 0):
                hg_rights = usergroup.hostgroup_rights
            else:
                hg_rights = usergroup.rights
            new_rights = self._get_updated_rights(hg_rights, permission, hostgroups)
            params[compat.usergroup_hostgroup_rights(self.version)] = [
                r.model_dump_api() for r in new_rights
            ]
        else:
            if self.version.release < (6, 2, 0):
                raise ZabbixAPIException(
                    "Template group rights are only supported in Zabbix 6.2.0 and later"
                )
            templategroups = [self.get_templategroup(tg) for tg in groups]
            tg_rights = usergroup.templategroup_rights
            new_rights = self._get_updated_rights(tg_rights, permission, templategroups)
            params[compat.usergroup_templategroup_rights(self.version)] = [
                r.model_dump_api() for r in new_rights
            ]
        try:
            self.usergroup.update(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update usergroup rights for {usergroup_name!r}"
            ) from e

    def _get_updated_rights(
        self,
        rights: List[ZabbixRight],
        permission: UsergroupPermission,
        groups: Union[List[HostGroup], List[TemplateGroup]],
    ) -> List[ZabbixRight]:
        new_rights: List[ZabbixRight] = []  # list of new rights to add
        rights = list(rights)  # copy rights (don't modify original)
        for group in groups:
            for right in rights:
                if right.id == group.groupid:
                    right.permission = permission
                    break
            else:
                new_rights.append(ZabbixRight(id=group.groupid, permission=permission))
        rights.extend(new_rights)
        return rights

    def get_proxy(
        self, name_or_id: str, select_hosts: bool = False, search: bool = True
    ) -> Proxy:
        """Fetches a single proxy matching the given name."""
        proxies = self.get_proxies(name_or_id, select_hosts=select_hosts, search=search)
        if not proxies:
            raise ZabbixNotFoundError(f"Proxy {name_or_id!r} not found")
        return proxies[0]

    def get_proxies(
        self,
        *names_or_ids: str,
        select_hosts: bool = False,
        search: bool = True,
        **kwargs: Any,
    ) -> List[Proxy]:
        """Fetches all proxies.

        NOTE: IDs and names cannot be mixed
        """
        params: ParamsType = {"output": "extend"}
        search_params: ParamsType = {}

        for name_or_id in names_or_ids:
            if name_or_id:
                if name_or_id.isnumeric():
                    params.setdefault("proxyids", []).append(name_or_id)
                else:
                    search_params.setdefault(
                        compat.proxy_name(self.version), []
                    ).append(name_or_id)

        if select_hosts:
            params["selectHosts"] = "extend"
        if search and search_params:
            params["search"] = search_params
            params["searchWildcardsEnabled"] = True
            params["searchByAny"] = True

        params.update(**kwargs)
        try:
            res = self.proxy.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Unknown error when fetching proxies") from e
        else:
            return [Proxy(**proxy) for proxy in res]

    def get_macro(
        self,
        host: Optional[Host] = None,
        macro_name: Optional[str] = None,
        search: bool = False,
        select_hosts: bool = False,
        select_templates: bool = False,
        sort_field: Optional[str] = "macro",
        sort_order: Optional[SortOrder] = None,
    ) -> Macro:
        """Fetches a macro given a host ID and macro name."""
        macros = self.get_macros(
            macro_name=macro_name,
            host=host,
            search=search,
            select_hosts=select_hosts,
            select_templates=select_templates,
            sort_field=sort_field,
            sort_order=sort_order,
        )
        if not macros:
            raise ZabbixNotFoundError("Macro not found")
        return macros[0]

    def get_hosts_with_macro(self, macro: str) -> List[Host]:
        """Fetches a macro given a host ID and macro name."""
        macros = self.get_macros(macro_name=macro)
        if not macros:
            raise ZabbixNotFoundError(f"Macro {macro!r} not found.")
        return macros[0].hosts

    def get_macros(
        self,
        macro_name: Optional[str] = None,
        host: Optional[Host] = None,
        search: bool = False,
        select_hosts: bool = False,
        select_templates: bool = False,
        sort_field: Optional[str] = "macro",
        sort_order: Optional[SortOrder] = None,
    ) -> List[Macro]:
        params: ParamsType = {"output": "extend"}

        if host:
            params.setdefault("search", {})["hostids"] = host.hostid

        if macro_name:
            params.setdefault("search", {})["macro"] = macro_name

        # Enable wildcard searching if we have one or more search terms
        if params.get("search"):
            params["searchWildcardsEnabled"] = True

        if select_hosts:
            params["selectHosts"] = "extend"

        if select_templates:
            params["selectTemplates"] = "extend"

        if sort_field:
            params["sortfield"] = sort_field
        if sort_order:
            params["sortorder"] = sort_order
        try:
            result = self.usermacro.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to retrieve macros") from e
        return [Macro(**macro) for macro in result]

    def get_global_macro(
        self,
        macro_name: Optional[str] = None,
        search: bool = False,
        sort_field: Optional[str] = "macro",
        sort_order: Optional[SortOrder] = None,
    ) -> Macro:
        """Fetches a global macro given a macro name."""
        macros = self.get_macros(
            macro_name=macro_name,
            search=search,
            sort_field=sort_field,
            sort_order=sort_order,
        )
        if not macros:
            raise ZabbixNotFoundError("Global macro not found")
        return macros[0]

    def get_global_macros(
        self,
        macro_name: Optional[str] = None,
        search: bool = False,
        sort_field: Optional[str] = "macro",
        sort_order: Optional[SortOrder] = None,
    ) -> List[GlobalMacro]:
        params: ParamsType = {"output": "extend", "globalmacro": True}

        if macro_name:
            params.setdefault("search", {})["macro"] = macro_name

        # Enable wildcard searching if we have one or more search terms
        if params.get("search"):
            params["searchWildcardsEnabled"] = True

        if sort_field:
            params["sortfield"] = sort_field
        if sort_order:
            params["sortorder"] = sort_order
        try:
            result = self.usermacro.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to retrieve global macros") from e

        return [GlobalMacro(**macro) for macro in result]

    def create_macro(self, host: Host, macro: str, value: str) -> str:
        """Creates a macro given a host ID, macro name and value."""
        try:
            resp = self.usermacro.create(hostid=host.hostid, macro=macro, value=value)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to create macro {macro!r} for host {host}"
            ) from e
        if not resp or not resp.get("hostmacroids"):
            raise ZabbixNotFoundError(
                f"No macro ID returned when creating macro {macro!r} for host {host}"
            )
        return resp["hostmacroids"][0]

    def create_global_macro(self, macro: str, value: str) -> str:
        """Creates a global macro given a macro name and value."""
        try:
            resp = self.usermacro.createglobal(macro=macro, value=value)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(f"Failed to create global macro {macro!r}.") from e
        if not resp or not resp.get("globalmacroids"):
            raise ZabbixNotFoundError(
                f"No macro ID returned when creating global macro {macro!r}."
            )
        return resp["globalmacroids"][0]

    def update_macro(self, macroid: str, value: str) -> str:
        """Updates a macro given a macro ID and value."""
        try:
            resp = self.usermacro.update(hostmacroid=macroid, value=value)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(f"Failed to update macro with ID {macroid}") from e
        if not resp or not resp.get("hostmacroids"):
            raise ZabbixNotFoundError(
                f"No macro ID returned when updating macro with ID {macroid}"
            )
        return resp["hostmacroids"][0]

    def update_host_inventory(self, host: Host, inventory: Dict[str, str]) -> str:
        """Updates a host inventory given a host and inventory."""
        try:
            resp = self.host.update(hostid=host.hostid, inventory=inventory)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update host inventory for host {host.host!r} (ID {host.hostid})"
            ) from e
        if not resp or not resp.get("hostids"):
            raise ZabbixNotFoundError(
                f"No host ID returned when updating inventory for host {host.host!r} (ID {host.hostid})"
            )
        return resp["hostids"][0]

    def update_host_proxy(self, host: Host, proxy: Proxy) -> str:
        """Updates a host's proxy."""
        params: ParamsType = {
            "hostid": host.hostid,
            compat.host_proxyid(self.version): proxy.proxyid,
        }
        try:
            resp = self.host.update(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update host proxy for host {host.host!r} (ID {host.hostid})"
            ) from e
        if not resp or not resp.get("hostids"):
            raise ZabbixNotFoundError(
                f"No host ID returned when updating proxy for host {host.host!r} (ID {host.hostid})"
            )
        return resp["hostids"][0]

    def clear_host_proxy(self, host: Host) -> str:
        """Clears a host's proxy."""
        params: ParamsType = {
            "hostid": host.hostid,
            compat.host_proxyid(self.version): None,
        }
        try:
            resp = self.host.massupdate(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(f"Failed to clear proxy on host {host}") from e
        if not resp or resp.get("hostids") is None:
            raise ZabbixNotFoundError(
                f"No host ID returned when clearing proxy on host {host}"
            )
        return resp["hostids"][0]

    def update_host_status(self, host: Host, status: MonitoringStatus) -> str:
        """Updates a host status given a host ID and status."""
        try:
            resp = self.host.update(hostid=host.hostid, status=status)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update host status for host {host.host!r} (ID {host.hostid})"
            ) from e
        if not resp or not resp.get("hostids"):
            raise ZabbixNotFoundError(
                f"No host ID returned when updating status for host {host.host!r} (ID {host.hostid})"
            )
        return resp["hostids"][0]

    # NOTE: maybe passing in a list of hosts to this is overkill?
    # Just pass in a list of host IDs instead?
    def move_hosts_to_proxy(self, hosts: List[Host], proxy: Proxy) -> None:
        """Moves a list of hosts to a proxy."""
        params: ParamsType = {
            "hosts": [{"hostid": host.hostid} for host in hosts],
            compat.host_proxyid(self.version): proxy.proxyid,
        }
        try:
            self.host.massupdate(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to move hosts {[str(host) for host in hosts]} to proxy {proxy.name!r}"
            ) from e

    def get_template(
        self,
        template_name_or_id: str,
        select_hosts: bool = False,
        select_templates: bool = False,
        select_parent_templates: bool = False,
    ) -> Template:
        """Fetch a single template given its name or ID."""
        templates = self.get_templates(
            template_name_or_id,
            select_hosts=select_hosts,
            select_templates=select_templates,
            select_parent_templates=select_parent_templates,
        )
        if not templates:
            raise ZabbixNotFoundError(f"Template {template_name_or_id!r} not found")
        return templates[0]

    def get_templates(
        self,
        *template_names_or_ids: str,
        select_hosts: bool = False,
        select_templates: bool = False,
        select_parent_templates: bool = False,
    ) -> List[Template]:
        """Fetches one or more templates given a name or ID."""
        params: ParamsType = {"output": "extend"}

        # TODO: refactor this along with other methods that take names or ids (or wildcards)
        if "*" in template_names_or_ids:
            template_names_or_ids = tuple()

        for name_or_id in template_names_or_ids:
            name_or_id = name_or_id.strip()
            is_id = name_or_id.isnumeric()
            if is_id:
                params.setdefault("templateids", []).append(name_or_id)
            else:
                params.setdefault("search", {}).setdefault("host", []).append(
                    name_or_id
                )
                params.setdefault("searchWildcardsEnabled", True)
                params.setdefault("searchByAny", True)
        if select_hosts:
            params["selectHosts"] = "extend"
        if select_templates:
            params["selectTemplates"] = "extend"
        if select_parent_templates:
            params["selectParentTemplates"] = "extend"
        try:
            templates = self.template.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Unable to fetch templates") from e
        return [Template(**template) for template in templates]

    def add_templates_to_groups(
        self,
        templates: List[Template],
        groups: Union[List[HostGroup], List[TemplateGroup]],
    ) -> None:
        try:
            self.template.massadd(
                templates=[
                    {"templateid": template.templateid} for template in templates
                ],
                groups=[{"groupid": group.groupid} for group in groups],
            )
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to add templates to group(s)") from e

    def link_templates_to_hosts(
        self, templates: List[Template], hosts: List[Host]
    ) -> None:
        """Links one or more templates to one or more hosts.

        Args:
            templates (List[str]): A list of template names or IDs
            hosts (List[str]): A list of host names or IDs
        """
        if not templates:
            raise ZabbixAPIException(
                "At least one template is required to link host to"
            )
        if not hosts:
            raise ZabbixAPIException(
                "At least one host is required to link templates to"
            )
        template_ids: ModifyTemplateParams = [
            {"templateid": template.templateid} for template in templates
        ]
        host_ids: ModifyHostParams = [{"hostid": host.hostid} for host in hosts]
        try:
            self.host.massadd(templates=template_ids, hosts=host_ids)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to link templates") from e

    def unlink_templates_from_hosts(
        self, templates: List[Template], hosts: List[Host], clear: bool = True
    ) -> None:
        """Unlinks and clears one or more templates from one or more hosts.

        Args:
            templates (List[Template]): A list of templates to unlink
            hosts (List[Host]): A list of hosts to unlink templates from
            clear (bool): Clear template from host when unlinking it.
        """
        if not templates:
            raise ZabbixAPIException("At least one template is required")
        if not hosts:
            raise ZabbixAPIException("At least one host is required")

        params: ParamsType = {
            "hostids": [h.hostid for h in hosts],
        }
        tids = [t.templateid for t in templates]
        if clear:
            params["templateids_clear"] = tids
        else:
            params["templateids"] = tids

        try:
            self.host.massremove(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to unlink and clear templates") from e

    def link_templates(
        self, source: List[Template], destination: List[Template]
    ) -> None:
        """Links one or more templates to one or more templates

        Destination templates are the templates that ultimately inherit the
        items and triggers from the source templates.

        Args:
            source (List[Template]): A list of templates to link from
            destination (List[Template]): A list of templates to link to
        """
        if not source:
            raise ZabbixAPIException("At least one source template is required")
        if not destination:
            raise ZabbixAPIException("At least one destination template is required")
        # NOTE: source templates are passed to templates_link param
        templates: ModifyTemplateParams = [
            {"templateid": template.templateid} for template in destination
        ]
        templates_link: ModifyTemplateParams = [
            {"templateid": template.templateid} for template in source
        ]
        try:
            self.template.massadd(templates=templates, templates_link=templates_link)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to link templates") from e

    def unlink_templates(
        self, source: List[Template], destination: List[Template], clear: bool = True
    ) -> None:
        """Unlinks template(s) from template(s) and optionally clears them.

        Destination templates are the templates that ultimately inherit the
        items and triggers from the source templates.

        Args:
            source (List[Template]): A list of templates to unlink
            destination (List[Template]): A list of templates to unlink source templates from
            clear (bool): Whether to clear the source templates from the destination templates. Defaults to True.
        """
        if not source:
            raise ZabbixAPIException("At least one source template is required")
        if not destination:
            raise ZabbixAPIException("At least one destination template is required")
        params: ParamsType = {
            "templateids": [template.templateid for template in destination],
            "templateids_link": [template.templateid for template in source],
        }
        # NOTE: despite what the docs say, we need to pass both templateids_link and templateids_clear
        # in order to unlink and clear templates. Only passing in templateids_clear will just
        # unlink the templates but not clear them (????) Absurd behavior.
        # This is NOT the case for host.massremove, where `templateids_clear` is sufficient...
        if clear:
            params["templateids_clear"] = params["templateids_link"]
        try:
            self.template.massremove(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to unlink template(s)") from e

    def link_templates_to_groups(
        self,
        templates: List[Template],
        groups: Union[List[HostGroup], List[TemplateGroup]],
    ) -> None:
        """Links one or more templates to one or more host/template groups.

        Callers must ensure that the right type of group is passed in depending
        on the Zabbix version:
            * Host groups for Zabbix < 6.2
            * Template groups for Zabbix >= 6.2

        Args:
            templates (List[str]): A list of template names or IDs
            groups (Union[List[HostGroup], List[TemplateGroup]]): A list of host/template groups
        """
        if not templates:
            raise ZabbixAPIException("At least one template is required")
        if not groups:
            raise ZabbixAPIException("At least one group is required")
        template_ids: ModifyTemplateParams = [
            {"templateid": template.templateid} for template in templates
        ]
        group_ids: ModifyGroupParams = [{"groupid": group.groupid} for group in groups]
        try:
            self.template.massadd(templates=template_ids, groups=group_ids)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to link template(s)") from e

    def remove_templates_from_groups(
        self,
        templates: List[Template],
        groups: Union[List[HostGroup], List[TemplateGroup]],
    ) -> None:
        """Removes template(s) from host/template group(s).

        Callers must ensure that the right type of group is passed in depending
        on the Zabbix version:
            * Host groups for Zabbix < 6.2
            * Template groups for Zabbix >= 6.2

        Args:
            templates (List[str]): A list of template names or IDs
            groups (Union[List[HostGroup], List[TemplateGroup]]): A list of host/template groups
        """
        # NOTE: do we even want to enforce this?
        if not templates:
            raise ZabbixAPIException("At least one template is required")
        if not groups:
            raise ZabbixAPIException("At least one group is required")
        try:
            self.template.massremove(
                templateids=[template.templateid for template in templates],
                groupids=[group.groupid for group in groups],
            )
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to unlink template from groups") from e

    def get_items(
        self,
        *names: str,
        templates: Optional[List[Template]] = None,
        hosts: Optional[List[Template]] = None,  # NYI
        proxies: Optional[List[Proxy]] = None,  # NYI
        search: bool = True,
        monitored: bool = False,
        select_hosts: bool = False,
        # TODO: implement interfaces
        # TODO: implement graphs
        # TODO: implement triggers
    ) -> List[Item]:
        params: ParamsType = {"output": "extend"}
        if names:
            params["search"] = {"name": names}
            if search:
                params["searchWildcardsEnabled"] = True
        if templates:
            params: ParamsType = {
                "templateids": [template.templateid for template in templates]
            }
        if monitored:
            params["monitored"] = monitored  # false by default in API
        if select_hosts:
            params["selectHosts"] = "extend"
        try:
            items = self.item.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Unable to fetch items") from e
        return [Item(**item) for item in items]

    def create_user(
        self,
        username: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        role: Optional[UserRole] = None,
        autologin: Optional[bool] = None,
        autologout: Union[str, int, None] = None,
        usergroups: Union[List[Usergroup], None] = None,
        media: Optional[List[UserMedia]] = None,
    ) -> str:
        # TODO: handle invalid password
        # TODO: handle invalid type
        params: ParamsType = {
            compat.user_name(self.version): username,
            "passwd": password,
        }

        if first_name:
            params["name"] = first_name
        if last_name:
            params["surname"] = last_name

        if role:
            params[compat.role_id(self.version)] = role

        if usergroups:
            params["usrgrps"] = [{"usrgrpid": ug.usrgrpid} for ug in usergroups]

        if autologin is not None:
            params["autologin"] = int(autologin)

        if autologout is not None:
            params["autologout"] = str(autologout)

        if media:
            params[compat.user_medias(self.version)] = [
                m.model_dump(mode="json") for m in media
            ]

        resp = self.user.create(**params)
        if not resp or not resp.get("userids"):
            raise ZabbixAPICallError(f"Creating user {username!r} returned no user ID.")
        return resp["userids"][0]

    def get_role(self, name_or_id: str) -> Role:
        """Fetches a role given its ID or name."""
        roles = self.get_roles(name_or_id)
        if not roles:
            raise ZabbixNotFoundError(f"Role {name_or_id!r} not found")
        return roles[0]

    def get_roles(self, name_or_id: Optional[str] = None) -> List[Role]:
        params: ParamsType = {"output": "extend"}
        if name_or_id is not None:
            if name_or_id.isdigit():
                params["roleids"] = name_or_id
            else:
                params["filter"] = {"name": name_or_id}
        roles = self.role.get(**params)
        return [Role(**role) for role in roles]

    def get_user(self, username: str) -> User:
        """Fetches a user given its username."""
        users = self.get_users(username)
        if not users:
            raise ZabbixNotFoundError(f"User with username {username!r} not found")
        return users[0]

    def get_users(
        self,
        username: Optional[str] = None,
        role: Optional[UserRole] = None,
        search: bool = False,
    ) -> List[User]:
        params: ParamsType = {"output": "extend"}
        filter_params: ParamsType = {}
        if search:
            params["searchWildcardsEnabled"] = True
        if username is not None:
            if search:
                params["search"] = {compat.user_name(self.version): username}
            else:
                filter_params[compat.user_name(self.version)] = username
        if role:
            filter_params[compat.role_id(self.version)] = role

        if filter_params:
            params["filter"] = filter_params

        users = self.user.get(**params)
        return [User(**user) for user in users]

    def delete_user(self, user: User) -> str:
        """Delete a user.

        Returns ID of deleted user.
        """
        try:
            resp = self.user.delete(user.userid)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to delete user {user.username!r} ({user.userid})"
            ) from e
        if not resp or not resp.get("userids"):
            raise ZabbixNotFoundError(
                f"No user ID returned when deleting user {user.username!r} ({user.userid})"
            )
        return resp["userids"][0]

    def update_user(
        self,
        user: User,
        current_password: Optional[str] = None,
        new_password: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        role: Optional[UserRole] = None,
        autologin: Optional[bool] = None,
        autologout: Union[str, int, None] = None,
    ) -> str:
        """Update a user. Returns ID of updated user."""
        query: ParamsType = {"userid": user.userid}
        if current_password and new_password:
            query["current_passwd"] = current_password
            query["passwd"] = new_password
        if first_name:
            query["name"] = first_name
        if last_name:
            query["surname"] = last_name
        if role:
            query[compat.role_id(self.version)] = role
        if autologin is not None:
            query["autologin"] = int(autologin)
        if autologout is not None:
            query["autologout"] = str(autologout)

        # Media and user groups are not supported in this method

        try:
            resp = self.user.update(**query)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update user {user.username!r} ({user.userid})"
            ) from e
        if not resp or not resp.get("userids"):
            raise ZabbixNotFoundError(
                f"No user ID returned when updating user {user.username!r} ({user.userid})"
            )
        return resp["userids"][0]

    def get_mediatype(self, name: str) -> MediaType:
        mts = self.get_mediatypes(name=name)
        if not mts:
            raise ZabbixNotFoundError(f"Media type {name!r} not found")
        return mts[0]

    def get_mediatypes(
        self, name: Optional[str] = None, search: bool = False
    ) -> List[MediaType]:
        params: ParamsType = {"output": "extend"}
        filter_params: ParamsType = {}
        if search:
            params["searchWildcardsEnabled"] = True
        if name is not None:
            if search:
                params["search"] = {"name": name}
            else:
                filter_params["name"] = name
        if filter_params:
            params["filter"] = filter_params
        resp = self.mediatype.get(**params)
        return [MediaType(**mt) for mt in resp]

    ## Maintenance
    def get_maintenance(self, maintenance_id: str) -> Maintenance:
        """Fetches a maintenance given its ID."""
        maintenances = self.get_maintenances(maintenance_ids=[maintenance_id])
        if not maintenances:
            raise ZabbixNotFoundError(f"Maintenance {maintenance_id!r} not found")
        return maintenances[0]

    def get_maintenances(
        self,
        maintenance_ids: Optional[List[str]] = None,
        hostgroups: Optional[List[HostGroup]] = None,
        hosts: Optional[List[Host]] = None,
        name: Optional[str] = None,
        select_hosts: bool = False,
    ) -> List[Maintenance]:
        params: ParamsType = {
            "output": "extend",
            "selectHosts": "extend",
            compat.param_host_get_groups(self.version): "extend",
            "selectTimeperiods": "extend",
        }
        filter_params: ParamsType = {}
        if maintenance_ids:
            params["maintenanceids"] = maintenance_ids
        if hostgroups:
            params["groupids"] = [hg.groupid for hg in hostgroups]
        if hosts:
            params["hostids"] = [h.hostid for h in hosts]
        if name:
            filter_params["name"] = name
        if filter_params:
            params["filter"] = filter_params
        resp = self.maintenance.get(**params)
        return [Maintenance(**mt) for mt in resp]

    def create_maintenance(
        self,
        name: str,
        active_since: datetime,
        active_till: datetime,
        description: Optional[str] = None,
        hosts: Optional[List[Host]] = None,
        hostgroups: Optional[List[HostGroup]] = None,
        data_collection: Optional[DataCollectionMode] = None,
    ) -> str:
        """Create a one-time maintenance definition."""
        if not hosts and not hostgroups:
            raise ZabbixAPIException("At least one host or hostgroup is required")
        params: ParamsType = {
            "name": name,
            "active_since": int(active_since.timestamp()),
            "active_till": int(active_till.timestamp()),
            "timeperiods": {
                "timeperiod_type": 0,
                "start_date": int(active_since.timestamp()),
                "period": int((active_till - active_since).total_seconds()),
            },
        }
        if description:
            params["description"] = description
        if hosts:
            if self.version.release >= (6, 0, 0):
                params["hosts"] = [{"hostid": h.hostid} for h in hosts]
            else:
                params["hostids"] = [h.hostid for h in hosts]
        if hostgroups:
            if self.version.release >= (6, 0, 0):
                params["groups"] = {"groupid": hg.groupid for hg in hostgroups}
            else:
                params["groupids"] = [hg.groupid for hg in hostgroups]
        if data_collection:
            params["maintenance_type"] = data_collection
        resp = self.maintenance.create(**params)
        if not resp or not resp.get("maintenanceids"):
            raise ZabbixAPICallError(f"Creating maintenance {name!r} returned no ID.")
        return resp["maintenanceids"][0]

    def update_maintenance(
        self,
        maintenance: Maintenance,
        hosts: Optional[List[Host]] = None,
    ) -> None:
        """Update a maintenance definition."""
        params: ParamsType = {"maintenanceid": maintenance.maintenanceid}
        if not hosts:
            raise ZabbixAPIException("At least one host is required")
        if self.version.release >= (6, 0, 0):
            params["hosts"] = [{"hostid": h.hostid} for h in hosts]
        else:
            params["hostids"] = [h.hostid for h in hosts]
        try:
            self.maintenance.update(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update maintenance {maintenance.name!r} ({maintenance.maintenanceid})"
            ) from e

    def remove_hosts_from_maintenance(
        self,
        maintenance: Maintenance,
        hosts: List[Host],
        delete_if_empty: bool = False,
    ) -> None:
        """Remove one or more hosts from a maintenance.

        Optionally also deletes the maintenance if no hosts remain."""
        # NOTE: we cannot be certain we can compare object identities here
        # so we use the actual host IDs to compare with instead.
        # E.g. a host fetched with `get_hosts` might differ from a host
        # with the same host ID in `maintenance.hosts`
        hids = [host.hostid for host in hosts]
        new_hosts = [host for host in maintenance.hosts if host.hostid not in hids]
        if not new_hosts:
            self.update_maintenance(maintenance, new_hosts)
        else:
            # Result is an empty maintenance - decide course of action
            hnames = ", ".join(h.host for h in hosts)
            raise ZabbixAPIException(
                f"Cannot remove host(s) {hnames} from maintenance {maintenance.name!r}"
            )

    def delete_maintenance(self, maintenance: Maintenance) -> List[str]:
        """Deletes one or more maintenances given their IDs

        Returns IDs of deleted maintenances.
        """
        try:
            resp = self.maintenance.delete(maintenance.maintenanceid)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to delete maintenance {maintenance.name!r}"
            ) from e
        if not resp or not resp.get("maintenanceids"):
            raise ZabbixNotFoundError(
                f"No maintenance IDs returned when deleting maintenance {maintenance.name!r}"
            )
        return resp["maintenanceids"]

    def get_triggers(
        self,
        trigger_ids: Union[str, List[str], None] = None,
        hosts: Optional[List[Host]] = None,
        hostgroups: Optional[List[HostGroup]] = None,
        templates: Optional[List[Template]] = None,
        description: Optional[str] = None,
        priority: Optional[TriggerPriority] = None,
        unacknowledged: bool = False,
        skip_dependent: Optional[bool] = None,
        monitored: Optional[bool] = None,
        active: Optional[bool] = None,
        expand_description: Optional[bool] = None,
        filter: Optional[Dict[str, Any]] = None,
        select_hosts: bool = False,
        sort_field: Optional[str] = "lastchange",
        sort_order: SortOrder = "DESC",
    ) -> List[Trigger]:
        params: ParamsType = {"output": "extend"}
        if hosts:
            params["hostids"] = [host.hostid for host in hosts]
        if description:
            params["search"] = {"description": description}
        if skip_dependent is not None:
            params["skipDependent"] = int(skip_dependent)
        if monitored is not None:
            params["monitored"] = int(monitored)
        if active is not None:
            params["active"] = int(active)
        if expand_description is not None:
            params["expandDescription"] = int(expand_description)
        if filter:
            params["filter"] = filter
        if trigger_ids:
            params["triggerids"] = trigger_ids
        if hostgroups:
            params["groupids"] = [hg.groupid for hg in hostgroups]
        if templates:
            params["templateids"] = [t.templateid for t in templates]
        if priority:
            params["filter"]["priority"] = priority
        if unacknowledged:
            params["withLastEventUnacknowledged"] = True
        if select_hosts:
            params["selectHosts"] = "extend"
        if sort_field:
            params["sortfield"] = sort_field
        if sort_order:
            params["sortorder"] = sort_order
        try:
            resp = self.trigger.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to fetch triggers") from e
        return [Trigger(**trigger) for trigger in resp]

    def update_trigger(
        self, trigger: Trigger, hosts: Optional[List[Host]] = None
    ) -> str:
        """Update a trigger."""
        params: ParamsType = {"triggerid": trigger.triggerid}
        if hosts:
            params["hostids"] = [host.hostid for host in hosts]
        try:
            resp = self.trigger.update(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError(
                f"Failed to update trigger {trigger.description!r} ({trigger.triggerid})"
            ) from e
        if not resp or not resp.get("triggerids"):
            raise ZabbixNotFoundError(
                f"No trigger ID returned when updating trigger {trigger.description!r} ({trigger.triggerid})"
            )
        return resp["triggerids"][0]

    def get_images(self, *image_names: str, select_image: bool = True) -> List[Image]:
        """Fetches images, optionally filtered by name(s)."""
        params: ParamsType = {"output": "extend"}
        if image_names:
            params["searchByAny"] = True
            params["search"] = {"name": image_names}
        if select_image:
            params["selectImage"] = True

        try:
            resp = self.image.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to fetch images") from e
        return [Image(**image) for image in resp]

    def get_maps(self, *map_names: str) -> List[Map]:
        """Fetches maps, optionally filtered by name(s)."""
        params: ParamsType = {"output": "extend"}
        if map_names:
            params["searchByAny"] = True
            params["search"] = {"name": map_names}

        try:
            resp = self.map.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to fetch maps") from e
        return [Map(**m) for m in resp]

    def get_media_types(self, *names: str) -> List[MediaType]:
        """Fetches media types, optionally filtered by name(s)."""
        params: ParamsType = {"output": "extend"}
        if names:
            params["searchByAny"] = True
            params["search"] = {"name": names}

        try:
            resp = self.mediatype.get(**params)
        except ZabbixAPIException as e:
            raise ZabbixAPICallError("Failed to fetch maps") from e
        return [MediaType(**m) for m in resp]

    def __getattr__(self, attr: str):
        """Dynamically create an object class (ie: host)"""
        return ZabbixAPIObjectClass(attr, self)


class ZabbixAPIObjectClass:
    def __init__(self, name: str, parent: ZabbixAPI):
        self.name = name
        self.parent = parent

    def __getattr__(self, attr: str) -> Any:
        """Dynamically create a method (ie: get)"""

        def fn(*args: Any, **kwargs: Any) -> Any:
            if args and kwargs:
                raise TypeError("Found both args and kwargs")

            return self.parent.do_request(f"{self.name}.{attr}", args or kwargs).result  # type: ignore

        return fn

    def get(self, *args: Any, **kwargs: Any) -> Any:
        """Provides per-endpoint overrides for the 'get' method"""
        if self.name == "proxy":
            # The proxy.get method changed from "host" to "name" in Zabbix 7.0
            # https://www.zabbix.com/documentation/6.0/en/manual/api/reference/proxy/get
            # https://www.zabbix.com/documentation/7.0/en/manual/api/reference/proxy/get
            output_kwargs = kwargs.get("output", None)
            params = ["name", "host"]
            if isinstance(output_kwargs, list) and any(
                p in output_kwargs for p in params
            ):
                output_kwargs = cast(List[str], output_kwargs)
                for param in params:
                    try:
                        output_kwargs.remove(param)
                    except ValueError:
                        pass
                output_kwargs.append(compat.proxy_name(self.parent.version))
                kwargs["output"] = output_kwargs
        return self.__getattr__("get")(*args, **kwargs)
