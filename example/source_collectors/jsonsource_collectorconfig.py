from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import TypeAdapter
from pydantic import ValidationError
from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.models import Host
from zabbix_auto_config.sourcecollectors import CollectorConfig


class JsonFileSourceConfig(CollectorConfig):
    __collector_name__ = "JSON file source"

    filename: Path = Path(__file__).parent / "hosts.json"
    opt_optional: Optional[str] = None
    opt_default: str = "default"


# Define a TypeAdapter for deserializing list of Host objects
HostList = TypeAdapter(list[Host])


def collect(**kwargs) -> list[Host]:
    config = JsonFileSourceConfig.from_kwargs(**kwargs)
    try:
        data = config.filename.read_text()
    except OSError as e:
        raise ZACException(
            f"Unable to read JSON hosts file '{config.filename}': {e}"
        ) from e

    try:
        return HostList.validate_json(data)
    except ValidationError as e:
        raise ZACException(f"Invalid JSON hosts file: {e}") from e
