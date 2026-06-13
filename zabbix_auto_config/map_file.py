"""Mapping file handling for ZAC.

This module only handles reading and parsing simple line-based mapping files.

See: zabbix_auto_config.macros for Macro mapping file handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.stdlib.get_logger()


@dataclass(frozen=True)
class MapFile:
    path: Path
    name: str  # "Property template map"
    required: bool = False  # tolerate missing file by default
    encoding: str = "utf-8"

    @property
    def logger(self) -> structlog.stdlib.BoundLogger:
        return logger.bind(file=str(self.path), name=self.name)

    def read(self) -> dict[str, list[str]]:
        try:
            content = self.path.read_text(encoding=self.encoding)
        except OSError as e:
            if self.required:
                raise RuntimeError(
                    f"Failed to read required {self.name} map file {self.path}: {e}"
                ) from e
            self.logger.error("Failed to read map file", error=str(e))
            return {}
        return self._parse(content)

    def _parse(self, content: str) -> dict[str, list[str]]:
        _map: dict[str, list[str]] = {}

        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            line = line.strip()

            # empty line or comment
            if not line or line.startswith("#"):
                continue

            try:
                line = line.partition("#")[0].strip()  # remove trailing comments
                key, value = line.split(":", 1)

                # Remove whitespace and check for empty key
                key = key.strip()
                if not key:
                    raise ValueError(
                        f"Empty key on line {lineno} in map file {self.path}"
                    )

                # Split on comma, but only keep non-empty values
                # remove trailing comments and whitespace
                values = list(filter(None, [s.strip() for s in value.split(",")]))
                if not values or all(not s for s in values):
                    raise ValueError(
                        f"Empty value(s) on line {lineno} in map file {self.path}"
                    )
            except ValueError:
                self.logger.warning(
                    "Invalid line in map file. Expected 'key:value'",
                    lineno=lineno,
                    line=line,
                )
                continue

            if key in _map:
                self.logger.warning("Duplicate key in map file", key=key, lineno=lineno)
                _map[key].extend(values)
            else:
                _map[key] = values

        # Final pass to remove duplicate values
        for key, values in _map.items():
            values_dedup = list(
                dict.fromkeys(values)
            )  # dict.fromkeys() guarantees order
            if len(values) != len(values_dedup):
                self.logger.warning("Ignoring duplicate values in map file.", key=key)
            _map[key] = values_dedup
        return _map
