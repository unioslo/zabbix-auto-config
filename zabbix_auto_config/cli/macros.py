from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import assert_never

import rich.box
import structlog.stdlib
import typer
from pydantic import ValidationError
from pydantic_core import ErrorDetails
from rich.console import Console
from rich.table import Table
from rich.text import Text

from zabbix_auto_config.cli._app import ZacApp
from zabbix_auto_config.macros import HostMacroResult
from zabbix_auto_config.macros import MacroMap
from zabbix_auto_config.macros import MacroMapFileIn
from zabbix_auto_config.macros import MacroValueType
from zabbix_auto_config.macros import PropertyValueIn
from zabbix_auto_config.macros import ResolvedMacro

if TYPE_CHECKING:
    from zabbix_auto_config.pyzabbix.types import Macro as ZabbixMacro

macros_app = ZacApp(
    name="macros",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

_CONSOLE = Console()

STYLE_ADD = "green"
STYLE_UPDATE = "yellow"
STYLE_REMOVE = "red"
STYLE_MACRO = "bold cyan"
BOX_TABLE = rich.box.ROUNDED

logger = structlog.stdlib.get_logger(__name__)


def _render_pydantic_error(e: ErrorDetails) -> str:
    """Render a Pydantic error detail as a Rich-formatted string without URLs."""
    parts: list[str] = []
    if loc := e.get("loc"):
        # We'll likely have a loc like `("macros", "{$MACRO_NAME}")`
        # Try to show just the macro name if the error stems from the
        # top-level "macros" key
        if loc[-1] == "macros" and len(loc) > 1:
            location = str(loc[1])
        else:  # fall back on entire location string joined by "."
            location = ".".join(str(lo) for lo in loc)
        parts.append(f"[{STYLE_MACRO}]{location}[/]")
    if msg := e.get("msg"):
        parts.append(f"  {msg}")  # indent
    return "\n".join(parts)


def _render_property_value(name: str, prop: PropertyValueIn) -> str:
    """Render a PropertyValueIn for display in a table."""
    if prop.template:
        v_str = str(prop.values) if prop.values else ""
    else:
        v_str = str(prop.value) if prop.value else ""
    return f"[bold magenta]{name}[/]: [green]{v_str}[/]"


def _render_properties(properties: dict[str, PropertyValueIn]) -> str:
    parts: list[str] = []
    for name, prop in properties.items():
        parts.append(_render_property_value(name, prop))
    return "\n".join(parts)


def _render_macro_map_file(m: MacroMapFileIn) -> Table:
    """Render the input macro mapping file as a table."""
    # NOTE: this does not recurse/dig into
    table = Table(
        title="Macro Definitions",
        show_header=True,
        show_lines=True,
        header_style="bold",
        box=BOX_TABLE,
    )
    table.add_column("Macro", overflow="fold")
    table.add_column("Template", overflow="fold")
    table.add_column("Properties")
    table.add_column("Contexts")
    table.add_column("Hosts")
    for macro_name, defn in m.macros.items():
        table.add_row(
            Text(macro_name, style=STYLE_MACRO),
            defn.template or "",
            _render_properties(defn.properties),
            ", ".join(c.context for c in defn.contexts),  # TODO: implement ctxs
            _render_properties(defn.hosts),
        )
    return table


@macros_app.command("validate")
def validate(
    ctx: typer.Context,
    file: Path | None = typer.Argument(  # noqa: B008
        None, help="Alternative path to macro mapping file"
    ),
    verbose: bool = typer.Option(  # noqa: B008
        False, "--verbose", "-v", help="Show traceback on failed validation"
    ),
    defs: bool = typer.Option(  # noqa: B008
        False,
        "--defs",
        help="Show validated macro definitions",
    ),
) -> None:
    """Validate a macro mapping file. Uses the default macro mapping file unless otherwise specified."""
    if not file:
        file = macros_app.get_config().zac.get_macro_map_file_path()

    try:
        in_file = MacroMap._load_infile(file)
    except Exception as e:
        # TODO: this is _not_ pretty! Need some nicer abstractions here.
        from rich.panel import Panel

        if verbose:
            _CONSOLE.print_exception()

        if isinstance(e, ValidationError):
            errors = e.errors(include_url=False)
            e_str = "\n".join(_render_pydantic_error(e) for e in errors)
            title = f"{len(errors)} errors"
        else:
            title = None
            e_str = str(e)

        p = Panel(_CONSOLE.render_str(e_str), title=title)
        _CONSOLE.print(p)
        _CONSOLE.print(
            f":cross_mark:Failed to validate macro mapping file {file}", style="red"
        )
        return  # Nothing more to do

    if defs:
        table = _render_macro_map_file(in_file)
        _CONSOLE.print(table)

    _CONSOLE.print(
        f":white_check_mark:Macro mapping file {file} is valid", style="green"
    )


class OutputMode(StrEnum):
    VERBOSE = "verbose"
    COMPACT = "compact"
    JSON = "json"


@macros_app.command("preview")
def preview_macros(
    ctx: typer.Context,
    hostname: str | None = typer.Option(  # noqa: B008
        None, "--hostname", help="Hostname to filter by. Required if --offline is set."
    ),
    offline: bool = typer.Option(  # noqa: B008
        False,
        "--offline",
        help="Preview macros from the last run without connecting to Zabbix or other sources.",
    ),
    properties: str | None = typer.Option(  # noqa: B008
        None,
        "--properties",
        help="Comma-separated list of properties to calculate macros for. Required for --offline to preview macros for specific properties without connecting to sources.",
    ),
    mode: OutputMode = typer.Option(  # noqa: B008
        OutputMode.VERBOSE,
        "--mode",
        "-m",
        help="Output mode for displaying macros.",
        case_sensitive=False,
    ),
) -> None:
    """
    Preview macros for hosts.

    If `hostname` is provided, only show macros for that host.
    """
    config = macros_app.get_config()
    macro_map = MacroMap.from_config(config)

    if offline:
        if not hostname:
            raise typer.BadParameter(
                "The --hostname option is required when using --offline to preview macros for a specific host."
            )
        if not properties:
            raise typer.BadParameter(
                "The --properties option is required when using --offline to preview macros for specific properties."
            )
        props = {p.strip() for p in properties.split(",")} if properties else set()
        results = _preview_offline(macro_map, hostname=hostname, properties=props)
    else:
        results = _preview_online(macro_map, hostname=hostname)

    if mode == OutputMode.VERBOSE:
        _render_verbose(results)
    elif mode == OutputMode.COMPACT:
        _render_summary(results)
    elif mode == OutputMode.JSON:
        _render_json(results)
    else:
        assert_never(mode)


def _preview_offline(
    macro_map: MacroMap, hostname: str, properties: set[str]
) -> dict[str, HostMacroResult]:
    """Preview macros to be assigned to a host based on its properties/hostname."""
    from zabbix_auto_config.models import Host
    from zabbix_auto_config.pyzabbix.types import Host as ZabbixHost

    mock_db_host = Host(
        enabled=True,
        hostname=hostname,
        properties=properties,
    )
    mock_zabbix_host = ZabbixHost(
        hostid="12345",
        host=hostname,
        proxyid="0",
        zabbix_agent=None,
        macros=[],
    )
    result = macro_map.resolve_macros(mock_db_host, mock_zabbix_host)
    return {hostname: result}


def _preview_online(
    macro_map: MacroMap, hostname: str | None
) -> dict[str, HostMacroResult]:
    """Preview macros for real hosts in Zabbix, optionally filtered by hostname."""
    from zabbix_auto_config.processing import ZabbixHostUpdater
    from zabbix_auto_config.pyzabbix.enums import MonitoringStatus
    from zabbix_auto_config.pyzabbix.types import Host as ZabbixHost
    from zabbix_auto_config.state import State

    # NOTE: for now we simply copy the code from ZabbixHostUpdater,
    # but in the future, the code for fetching hosts from Zabbix and DB,
    # and determining hosts to modify should be generalized, testable
    # and used by both the main app and this preview command.
    config = macros_app.get_config()

    updater = ZabbixHostUpdater("macro_preview", State(), config)
    db_hosts = updater.get_db_hosts()
    zhosts = updater.api.get_hosts(
        hostname or "",  # bad hack to work around str *args unpacking
        status=MonitoringStatus.ON,
        flags=0,
        select_interfaces=True,
        select_inventory=True,
        select_templates=True,
        select_tags=True,
        select_groups=True,
        select_macros=True,
    )
    zabbix_hosts = {host.host: host for host in zhosts}

    zabbix_managed_hosts: list[ZabbixHost] = []
    zabbix_manual_hosts: list[ZabbixHost] = []

    for host in zabbix_hosts.values():
        hostgroup_names = [group.name for group in host.groups]
        if config.zabbix.hostgroup_manual in hostgroup_names:
            zabbix_manual_hosts.append(host)
        else:
            zabbix_managed_hosts.append(host)

    db_hostnames = set(db_hosts)
    zabbix_managed_hostnames = {host.host for host in zabbix_managed_hosts}
    zabbix_manual_hostnames = {host.host for host in zabbix_manual_hosts}

    managed_hosts = list(
        db_hostnames.intersection(zabbix_managed_hostnames) - zabbix_manual_hostnames
    )

    results: dict[str, HostMacroResult] = {}
    for host_name in managed_hosts:
        result = macro_map.resolve_macros(db_hosts[host_name], zabbix_hosts[host_name])
        results[host_name] = result

    return results


def _is_secret(macro_type: int | None, value_type: MacroValueType | None) -> bool:
    """Determine if a macro if secret or not."""
    return macro_type == 1 or value_type == MacroValueType.SECRET


def _mask(value: str | None, secret: bool) -> str:
    """Mask a macro value (if necessary)."""
    return "***" if secret else (value or "")


def _build_host_table(hostname: str, result: HostMacroResult) -> Table:
    """Create a detailed table object showing macro changes for a host."""
    # TODO: use Text with style to render these parts. How?
    parts: list[str] = []
    if result.add:
        parts.append(f"[green]+{len(result.add)}[/green]")
    if result.update:
        parts.append(f"[yellow]~{len(result.update)}[/yellow]")
    if result.remove:
        parts.append(f"[red]-{len(result.remove)}[/red]")

    table = Table(
        title=f"[bold]{hostname}[/bold]  ({', '.join(parts)})",
        show_header=True,
        header_style="bold",
        box=BOX_TABLE,
    )
    table.add_column("Action", justify="center", no_wrap=True)
    table.add_column("Macro", no_wrap=True)
    table.add_column("Old", no_wrap=True)
    table.add_column("New", no_wrap=True)

    def fmt_macro(macro_str: str) -> Text:
        return Text(macro_str, style=STYLE_MACRO)

    for macro_str, resolved in sorted(result.add.items()):
        secret = _is_secret(None, resolved.value_type)
        table.add_row(
            Text("+", style=STYLE_ADD),
            fmt_macro(macro_str),
            "",
            Text(_mask(resolved.value, secret), style=STYLE_ADD),
        )

    for macro_str, (current, desired) in sorted(result.update.items()):
        secret = _is_secret(current.type, desired.value_type)
        table.add_row(
            Text("~", style=STYLE_UPDATE),
            fmt_macro(macro_str),
            Text(_mask(current.value, secret), style=STYLE_REMOVE),
            Text(_mask(desired.value, secret), style=STYLE_UPDATE),
        )

    for macro_str, current in sorted(result.remove.items()):
        secret = _is_secret(current.type, None)
        table.add_row(
            Text("-", style=STYLE_REMOVE),
            fmt_macro(macro_str),
            Text(_mask(current.value, secret), style=STYLE_REMOVE),
            "",
        )

    return table


def _render_summary(results: dict[str, HostMacroResult]) -> None:
    """Render a summary of hosts that will have macros added/updated/removed."""
    changed = {h: r for h, r in results.items() if r.add or r.update or r.remove}
    if not changed:
        _CONSOLE.print("No macro changes.")
        return

    table = Table(show_header=True, header_style="bold", box=BOX_TABLE)
    table.add_column("Host")
    table.add_column("Add", justify="right")
    table.add_column("Update", justify="right")
    table.add_column("Remove", justify="right")

    total_add = total_update = total_remove = 0
    for host, result in sorted(changed.items()):
        n_add, n_update, n_remove = (
            len(result.add),
            len(result.update),
            len(result.remove),
        )
        total_add += n_add
        total_update += n_update
        total_remove += n_remove
        table.add_row(
            host,
            # Style only if we have changes
            Text(str(n_add), style=STYLE_ADD if n_add else ""),
            Text(str(n_update), style=STYLE_UPDATE if n_update else ""),
            Text(str(n_remove), style=STYLE_REMOVE if n_remove else ""),
        )

    _CONSOLE.print(table)
    n = len(changed)
    _CONSOLE.print(
        f"{n} host{'s' if n != 1 else ''} affected — {total_add} to add, {total_update} to update, {total_remove} to remove"
    )


def _render_verbose(results: dict[str, HostMacroResult]) -> None:
    """Render a detailed table for each host."""
    changed = {h: r for h, r in results.items() if r.add or r.update or r.remove}
    if not changed:
        _CONSOLE.print("No macro changes.")
        return

    total_add = total_update = total_remove = 0
    for host, result in sorted(changed.items()):
        total_add += len(result.add)
        total_update += len(result.update)
        total_remove += len(result.remove)
        _CONSOLE.print(_build_host_table(host, result))

    n = len(changed)
    _CONSOLE.print(
        f"{n} host{'s' if n != 1 else ''} affected — {total_add} to add, {total_update} to update, {total_remove} to remove"
    )


def _render_json(results: dict[str, HostMacroResult]) -> None:
    """Render results as JSON."""
    import json

    def _serialize_macro_type(macro: ResolvedMacro | ZabbixMacro) -> int:
        if isinstance(macro, ResolvedMacro):
            return macro.value_type.to_zabbix()
        else:
            return macro.type

    def _serialize_macro(macro: ResolvedMacro | ZabbixMacro) -> dict[str, Any]:
        return {
            "value": macro.value,
            "description": macro.description,
            "type": _serialize_macro_type(macro),
        }

    def _serialize_result(result: HostMacroResult) -> dict[str, Any]:
        return {
            "add": {k: _serialize_macro(v) for k, v in result.add.items()},
            "update": {
                k: {
                    "current": _serialize_macro(c),
                    "desired": _serialize_macro(d),
                }
                for k, (c, d) in result.update.items()
            },
            "remove": {k: _serialize_macro(v) for k, v in result.remove.items()},
        }

    serializable = {host: _serialize_result(result) for host, result in results.items()}
    _CONSOLE.print(json.dumps(serializable, indent=2))
