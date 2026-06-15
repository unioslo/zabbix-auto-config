from __future__ import annotations

from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from zabbix_auto_config.config import Settings


class ZacApp(typer.Typer):
    _config: Settings | None = None  # Set by main callback

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def configure(self, config: Settings) -> None:
        """Configure the app with the given config."""
        self.set_config(config)
        # Run configuration in sub-apps as well, if they exist
        for group in self.registered_groups:
            if isinstance(group.typer_instance, ZacApp):
                group.typer_instance.configure(config)

    def set_config(self, config: Settings) -> None:
        """Set the global config object.

        Args:
            config (Settings): Config object to set.
        """
        self._config = config

    def get_config(self) -> Settings:
        """Get the global config object.

        Raises:
            RuntimeError: Config has not been set yet.

        Returns:
            Settings: The global config object.
        """
        if self._config is None:
            raise RuntimeError("Config not set")
        return self._config
