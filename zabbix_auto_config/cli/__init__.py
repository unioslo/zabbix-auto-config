from __future__ import annotations

from zabbix_auto_config.cli._app import ZacApp
from zabbix_auto_config.cli.macros import macros_app

app = ZacApp(
    add_completion=False, pretty_exceptions_enable=False, invoke_without_command=True
)
app.add_typer(macros_app, name="macros", help="Manage macros")

__all__ = [
    "app",
]
