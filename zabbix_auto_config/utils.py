from __future__ import annotations

import copy
import ipaddress
import multiprocessing
import queue
import re
from collections import defaultdict
from collections.abc import MutableMapping
from dataclasses import dataclass
from dataclasses import field
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import Optional
from typing import TypedDict
from typing import Union

import structlog
from typing_extensions import NamedTuple

from zabbix_auto_config.pyzabbix.types import HostTag

if TYPE_CHECKING:
    from zabbix_auto_config._types import ZacTags


logger = structlog.stdlib.get_logger(__name__)


def is_valid_regexp(pattern: str):
    try:
        re.compile(pattern)
        return True
    except (re.error, TypeError):
        return False


def is_valid_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def zabbix_tags2zac_tags(zabbix_tags: list[HostTag]) -> ZacTags:
    return {(tag.tag, tag.value) for tag in zabbix_tags}


def zac_tags2zabbix_tags(zac_tags: ZacTags) -> list[HostTag]:
    return [HostTag(tag=tag[0], value=tag[1]) for tag in zac_tags]


def read_map_file(path: Union[str, Path]) -> dict[str, list[str]]:
    _map: dict[str, list[str]] = {}

    with open(path) as f:
        log = logger.bind(file=str(path))
        for lineno, line in enumerate(f, start=1):
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
                    raise ValueError(f"Emtpy key on line {lineno} in map file {path}")

                # Split on comma, but only keep non-empty values
                # remove trailing comments and whitespace
                values = list(filter(None, [s.strip() for s in value.split(",")]))
                if not values or all(not s for s in values):
                    raise ValueError(
                        f"Empty value(s) on line {lineno} in map file {path}"
                    )
            except ValueError:
                log.warning(
                    "Invalid line in map file. Expected 'key:value'",
                    lineno=lineno,
                    line=line,
                )
                continue

            if key in _map:
                log.warning("Duplicate key in map file", key=key, lineno=lineno)
                _map[key].extend(values)
            else:
                _map[key] = values

    # Final pass to remove duplicate values
    for key, values in _map.items():
        values_dedup = list(dict.fromkeys(values))  # dict.fromkeys() guarantees order
        if len(values) != len(values_dedup):
            logger.warning("Ignoring duplicate values in map file.", key=key)
        _map[key] = values_dedup
    return _map


def with_prefix(
    text: str,
    prefix: str,
    separator: str = "-",
) -> str:
    """Replaces the prefix of `text` with `prefix`. Assumes the separator
    between the prefix and the text is `separator` (default: "-").

    Parameters
    ----
    text: str
        The text to format.
    prefix: str
        The prefix to add to `text`.
    separator: str
        The separator between the prefix and the text.

    Returns
    -------
    str
        The formatted string.
    """
    if not all(s for s in (text, prefix, separator)):
        raise ValueError("Text, prefix, and separator cannot be empty")

    _, _, suffix = text.partition(separator)

    # Unable to split text, nothing to do
    if not suffix:
        raise ValueError(
            f"Could not find prefix in {text!r} with separator {separator!r}"
        )

    groupname = f"{prefix}{suffix}"
    if not prefix.endswith(separator) and not suffix.startswith(separator):
        logger.warning(
            "Prefix for group name does not contain separator",
            prefix=prefix,
            groupname=groupname,
            separator=separator,
        )
    return groupname


def mapping_values_with_prefix(
    m: MutableMapping[str, list[str]],
    prefix: str,
    separator: str = "-",
) -> MutableMapping[str, list[str]]:
    """Calls `with_prefix` on all items in the values (list) in the mapping `m`."""
    m = copy.copy(m)  # don't modify the original mapping
    for key, value in m.items():
        new_values = []
        for v in value:
            try:
                new_value = with_prefix(text=v, prefix=prefix, separator=separator)
            except ValueError:
                logger.warning("Unable to replace prefix", text=v, prefix=prefix)
                continue
            new_values.append(new_value)
        m[key] = new_values
    return m


def drain_queue(q: multiprocessing.Queue[Any]) -> None:
    """Drains a multiprocessing.Queue by calling `queue.get_nowait()` until the queue is empty."""
    while not q.empty():
        try:
            q.get_nowait()
        except queue.Empty:
            break


def format_timedelta(td: Optional[timedelta] = None) -> str:
    """Format a timedelta object showing only hours, minutes, and seconds.

    Args:
        td: The timedelta object to format

    Returns:
        A string representation in the format "HH:MM:SS"
    """
    if td is None:
        return "00:00:00"

    # Convert to total seconds and handle sign
    total_seconds = int(td.total_seconds())
    sign = "-" if total_seconds < 0 else ""
    total_seconds = abs(total_seconds)

    # Convert to hours, minutes, seconds
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return f"{sign}{hours:02d}:{minutes:02d}:{seconds:02d}"


def write_file(path: Union[str, Path], content: str, end: str = "\n") -> None:
    """Writes `content` to `path`. Ensures content ends with a given character."""
    path = Path(path)
    # Ensure parent dirs exist
    make_parent_dirs(path)

    try:
        with open(path, "w") as f:
            if end and not content.endswith(end):
                content += end
            f.write(content)
    except OSError as e:
        logger.error("Failed to write to file", file=str(path), error=str(e))
        raise


def make_parent_dirs(path: Union[str, Path]) -> Path:
    """Attempts to create all parent directories given a path.

    NOTE: Intended for usage with Pydantic models, and as such it will raise
    a ValueError instead of OSError if the directory cannot be created."""
    path = Path(path)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise ValueError(f"Failed to create parent directories for {path}: {e}") from e
    return path


from pydantic import BaseModel
from pydantic import GetCoreSchemaHandler
from pydantic_core import PydanticCustomError
from pydantic_core import core_schema

# class PropertyMacroMap(BaseModel):
#     text: str
#     regex: str


class UserMacroName(str):
    """A string subclass representing a Zabbix user macro name. Used for validation and type hinting."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type[Any], handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Return a pydantic core schema for validating a zabbix macro name."""
        return core_schema.with_info_before_validator_function(
            cls._validate,
            core_schema.str_schema(),
        )

    @classmethod
    def _validate(cls, __input_value: str, _: Any) -> str:
        """Validate a Zabbix macro name from the provided str value.

        Args:
            __input_value: The str value to be validated.
            _: The source type to be converted.

        Returns:
            str: The parsed Zabbix macro name.

        """
        return cls.validate_macro_name(__input_value)

    @staticmethod
    def validate_macro_name(value: str) -> str:
        """Validate a Zabbix macro name from the provided str value."""
        if not is_valid_macro_name(value):
            raise PydanticCustomError("macro_name_format", "Unrecognized format")
        return value


MACRO_NAME_PATTERN = re.compile(r"^\{\$[A-Z0-9_.]+\}$")


def is_valid_macro_name(name: str) -> bool:
    """Check if the provided name is a valid Zabbix macro name."""
    return bool(MACRO_NAME_PATTERN.match(name))


@lru_cache(maxsize=1000)
def fmt_macro_name(macro: str) -> str:
    """Format macro name for use in a query."""
    macro = macro.strip()
    if not macro:
        # TODO: More specific exception class
        raise ValueError("Macro name cannot be empty.")
    if not macro.isupper():
        macro = macro.upper()
    if not macro.startswith("{"):
        macro = "{" + macro
    if not macro.endswith("}"):
        macro = macro + "}"
    if not macro[1] == "$":  # NOTE: refactor could break this
        macro = "{$" + macro[1:]
    if not is_valid_macro_name(macro):
        raise ValueError(f"Invalid macro name {macro!r}")
    return macro


class PropertyMacroMapFileIn(BaseModel):
    # Mappings of macro names to properties -> macro values
    text: dict[str, dict[str, str]]
    regex: dict[str, dict[str, str]]


class MappedMacro(NamedTuple):
    """A macro mapped to a property from the property-macro mapping file."""

    name: str
    value: str
    regex: bool = False


class UnresolvedMacro(TypedDict):
    """A macro and its values derived from the properties associated with it.

    An intermediate data structure that holds all mapped macro values
    based on a host's properties before resolving them into a final
    macro to add to the host in Zabbix.
    """

    name: str
    values: list[str]
    regex: bool


def resolve_macros(macros: list[UnresolvedMacro]) -> dict[str, str]:
    """Resolve a list of UnresolvedMacro into a dict of macro name to resolved value.

    If a macro has multiple values, the values are joined with a comma.
    If a macro has any regex values, the resolved value is prefixed with "regex:".
    """
    resolved: dict[str, str] = {}
    for macro in macros:
        name = macro["name"]
        values = macro["values"]
        regex = macro["regex"]
        if not values:  # TODO: remove, we should have resolved this here
            logger.warning("Macro has no values. Ignoring.", name=macro["name"])
            continue

        if not regex:
            if name not in resolved:
                resolved[name] = values[0]
            else:
                logger.warning(
                    "Duplicate macro name with non-regex value. Ignoring.",
                    name=name,
                    value=values,
                )
            continue  # continue to next, nothing more to do

        if len(values) > 1:
            # Wrap multiple values in parentheses and separate with pipe
            value = f"({'|'.join(values)})"
        else:
            value = values[0]
        if validate_regexp(value):
            resolved[name] = value
    return resolved


@lru_cache(maxsize=1000)
def validate_regexp(regex: str) -> bool:
    """Validate a regex pattern and cache the result for future calls."""
    try:
        _ = re.compile(regex)
        return True
    except re.error:
        return False


def _defaultdict_list() -> defaultdict[str, list[MappedMacro]]:
    return defaultdict(list)


@dataclass
class PropertyMacroMapping:
    text: defaultdict[str, list[MappedMacro]] = field(default_factory=_defaultdict_list)
    regex: defaultdict[str, list[MappedMacro]] = field(
        default_factory=_defaultdict_list
    )

    # Strategy: if macro is defined in both text and regex
    # the text properties are ignored altogether! <-- NOT TRUE!

    def get_macros(self, properties: list[str]) -> dict[str, str]:
        """Get the macro associated with the properties."""
        macros: dict[str, UnresolvedMacro] = {}
        for property_name in properties:
            # Resolve regex first!
            if property_name in self.regex:
                for macro in self.regex[property_name]:
                    # TODO: validate regex
                    if macro.name not in macros:
                        macros[macro.name] = UnresolvedMacro(
                            name=macro.name,
                            values=[macro.value],
                            regex=True,
                        )
                    else:
                        macros[macro.name]["values"].append(macro.value)
                        macros[macro.name]["regex"] = True  # mark macro as regex

            if property_name in self.text:
                for macro in self.text[property_name]:
                    if macro.name not in macros:
                        macros[macro.name] = UnresolvedMacro(
                            name=macro.name,
                            values=[macro.value],
                            regex=False,
                        )
                    else:
                        macros[macro.name]["values"].append(macro.value)

        # After collecting all macros that map to the properties,
        # resolve them into the final macro values to add to Zabbix.
        resolved_macros = resolve_macros(list(macros.values()))
        return resolved_macros


from yaml import load

try:
    from yaml import CDumper as Dumper
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


def read_property_macro_map(path: Union[str, Path]) -> PropertyMacroMapping:
    try:
        with open(path) as f:
            data = load(f, Loader=Loader)
    except Exception as e:
        logger.error(
            "Failed to read property macro map file", file=str(path), error=str(e)
        )
        raise

    # Validate basic shape of data (this must be valid!)
    try:
        prop_map = PropertyMacroMapFileIn.model_validate(data)
    except Exception as e:
        logger.error("Invalid property macro map file", file=str(path), error=str(e))
        raise

    mapping = PropertyMacroMapping()

    for macros, regex in [(prop_map.text, False), (prop_map.regex, True)]:
        for property_name, macro_dict in macros.items():
            for macro_name, macro_value in macro_dict.items():
                try:
                    fmt_name = fmt_macro_name(macro_name)
                except ValueError as e:
                    logger.error(
                        "Invalid macro name in property macro map file. Ignoring.",
                        file=str(path),
                        macro_name=macro_name,
                        error=str(e),
                    )
                    continue

                mapped_macro = MappedMacro(
                    name=fmt_name, value=macro_value, regex=regex
                )
                # Ensure value is valid regex (even if's just a regular string)
                if regex:
                    if not validate_regexp(macro_value):
                        logger.error(
                            "Invalid regex in property macro map file. Ignoring.",
                            file=str(path),
                            macro_name=macro_name,
                            macro_value=macro_value,
                        )
                        continue

                if regex:
                    mapping.regex[property_name].append(mapped_macro)
                else:
                    mapping.text[property_name].append(mapped_macro)

    return mapping
