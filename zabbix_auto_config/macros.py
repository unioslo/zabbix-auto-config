from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any
from typing import Optional
from typing import Union

import structlog.stdlib
import yaml
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import PrivateAttr
from pydantic import field_validator
from pydantic import model_validator

try:
    from yaml import CSafeLoader as _YamlLoader
except ImportError:
    from yaml import SafeLoader as _YamlLoader  # type: ignore[assignment]

logger = structlog.stdlib.get_logger(__name__)

MACRO_NAME_PATTERN = re.compile(r"^\{\$[A-Z0-9_.]+\}$")


def is_valid_macro_name(name: str) -> bool:
    """Check if the provided name is a valid Zabbix user macro name."""
    return bool(MACRO_NAME_PATTERN.match(name))


@lru_cache(maxsize=1000)
def fmt_macro_name(macro: str) -> str:
    """Normalize and validate a Zabbix user macro name."""
    macro = macro.strip()
    if not macro:
        raise ValueError("Macro name cannot be empty.")
    if not macro.isupper():
        macro = macro.upper()
    if not macro.startswith("{"):
        macro = "{" + macro
    if not macro.endswith("}"):
        macro = macro + "}"
    if macro[1] != "$":
        macro = "{$" + macro[1:]
    if not is_valid_macro_name(macro):
        raise ValueError(f"Invalid macro name {macro!r}")
    return macro


@lru_cache(maxsize=1000)
def validate_regexp(regex: str) -> bool:
    """Validate a regex pattern and cache the result for future calls."""
    try:
        re.compile(regex)
        return True
    except re.error:
        return False


# ----- Resolved macro model (internal + public) -----


class ContextType(str, Enum):
    """Type of macro context."""

    STATIC = "static"
    REGEX = "regex"


class CombineStrategy(str, Enum):
    """Strategy for combining multiple property contributions to the same macro identity."""

    TEXT = "text"  # alphabetically first contributing property wins
    REGEX = "regex"  # values join into (v1|v2|...)


class MacroType(str, Enum):
    """Macro value type."""

    TEXT = "text"  # Zabbix usermacro type=0
    SECRET = "secret"  # type=1
    VAULT = "vault"  # type=2


@dataclass(frozen=True)
class MacroIdentity:
    """Unique identity of a Zabbix user macro: (name, context, context_type)."""

    name: str
    context: Optional[str] = None
    context_type: ContextType = ContextType.STATIC

    def to_zabbix(self) -> str:
        """Format as the macro string Zabbix expects (e.g. '{$M:"ctx"}').

        Adds context to macro if present.
        """
        if self.context is None:
            return self.name
        base = self.name[:-1]  # strip trailing "}"
        ctx = self.context
        if self.context_type == ContextType.REGEX:
            escaped = ctx.replace('"', '\\"')
            return f'{base}:regex:"{escaped}"' + "}"
        if "}" in ctx or ctx.startswith('"'):
            escaped = ctx.replace('"', '\\"')
            return f'{base}:"{escaped}"' + "}"
        return f"{base}:{ctx}" + "}"


@dataclass
class MacroValue:
    """Value contribution from one property mapping."""

    value: str
    description: Optional[str] = None


@dataclass
class MacroDefinition:
    """All metadata for one macro identity, plus its property->value table."""

    identity: MacroIdentity
    description: Optional[str] = None
    macro_type: MacroType = MacroType.TEXT
    combine: CombineStrategy = CombineStrategy.TEXT
    properties: dict[str, MacroValue] = field(default_factory=dict)


@dataclass
class ResolvedMacro:
    """A macro resolved for a specific host's property set."""

    identity: MacroIdentity
    value: str
    description: Optional[str] = None
    macro_type: MacroType = MacroType.TEXT

    @property
    def name(self) -> str:
        return self.identity.to_zabbix()


# ----- Pydantic input models (YAML schema) -----


class PropertyValueIn(BaseModel):
    """Per-property value entry. Accepts scalar shorthand or expanded form."""

    model_config = ConfigDict(extra="forbid")

    value: str
    description: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _coerce_scalar(cls, data: Any) -> Any:
        """Coerce a single scalar value to the expanded form with a 'value' key."""
        if isinstance(data, (str, int, float, bool)):
            return {"value": str(data)}
        return data


class MacroContextIn(BaseModel):
    """A non-default-context variant of a macro definition."""

    model_config = ConfigDict(extra="forbid")

    context: str
    context_type: ContextType = ContextType.STATIC
    combine: CombineStrategy = CombineStrategy.TEXT
    description: Optional[str] = None
    properties: dict[str, PropertyValueIn]

    @model_validator(mode="after")
    def _validate_regex_context(self) -> MacroContextIn:
        if self.context_type == ContextType.REGEX and not validate_regexp(self.context):
            raise ValueError(f"Invalid regex context: {self.context!r}")
        return self


class MacroDefIn(BaseModel):
    """Top-level macro definition entry."""

    model_config = ConfigDict(extra="forbid")

    description: Optional[str] = None
    type: MacroType = MacroType.TEXT
    combine: CombineStrategy = CombineStrategy.TEXT
    properties: dict[str, PropertyValueIn] = Field(default_factory=dict)
    contexts: list[MacroContextIn] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_some_mapping(self) -> MacroDefIn:
        if not self.properties and not self.contexts:
            raise ValueError("Macro must define `properties` or `contexts`")
        return self


class MacroMapFileIn(BaseModel):
    """Top-level YAML schema for property-macro mapping files."""

    model_config = ConfigDict(extra="forbid")

    macros: dict[str, MacroDefIn] = Field(default_factory=dict)

    @field_validator("macros")
    @classmethod
    def _validate_macro_keys(cls, v: dict[str, MacroDefIn]) -> dict[str, MacroDefIn]:
        for name in v:
            if not is_valid_macro_name(name):
                raise ValueError(f"Invalid macro name key: {name!r}")
        return v


# ----- Property-to-macro mapping (resolved, public API) -----


class PropertyMacroMapping(BaseModel):
    """All macro definitions, indexed by the property names that contribute to them."""

    definitions: list[MacroDefinition] = Field(default_factory=list)
    _by_property: dict[str, list[MacroDefinition]] = PrivateAttr(
        default_factory=lambda: defaultdict(list)
    )

    def add(self, definition: MacroDefinition) -> None:
        self.definitions.append(definition)
        for prop in definition.properties:
            self._by_property[prop].append(definition)

    def get_zabbix_macros(self, properties: Iterable[str]) -> dict[str, str]:
        """Resolve final macros for the given property set.

        Returned dict is keyed by the Zabbix macro string (including context)
        and valued by the resolved final macro value (e.g. "foo" or "(v1|v2)"),
        ready to be sent to Zabbix API.
        """
        resolved_map = self.get_macros(properties)
        return {m.name: m.value for m in resolved_map.values()}

    def get_macros(self, properties: Iterable[str]) -> dict[str, ResolvedMacro]:
        """Resolve final macros for the given property set.

        Returned dict is keyed by the Zabbix macro string (including context).
        """
        per_identity: dict[
            MacroIdentity, tuple[MacroDefinition, list[tuple[str, MacroValue]]]
        ] = {}
        seen_props: set[str] = set()
        for prop in properties:
            if prop in seen_props:
                continue
            seen_props.add(prop)
            for defn in self._by_property.get(prop, []):
                mv = defn.properties.get(prop)
                if mv is None:
                    continue
                slot = per_identity.setdefault(defn.identity, (defn, []))
                slot[1].append((prop, mv))

        result: dict[str, ResolvedMacro] = {}
        for identity, (defn, contributions) in per_identity.items():
            contributions.sort(key=lambda c: c[0])

            if defn.combine == CombineStrategy.TEXT:
                winning_prop, mv = contributions[0]
                if len(contributions) > 1:
                    logger.warning(
                        "Multiple text-combine values for macro; using alphabetically first property",
                        macro=identity.to_zabbix(),
                        winning_property=winning_prop,
                        ignored_properties=[c[0] for c in contributions[1:]],
                    )
                resolved_value = mv.value
                description = mv.description or defn.description
            else:  # REGEX
                values = [mv.value for _, mv in contributions]
                resolved_value = (
                    f"({'|'.join(values)})" if len(values) > 1 else values[0]
                )
                if not validate_regexp(resolved_value):
                    logger.error(
                        "Resolved regex macro is invalid; skipping",
                        macro=identity.to_zabbix(),
                        value=resolved_value,
                    )
                    continue
                description = next(
                    (mv.description for _, mv in contributions if mv.description),
                    defn.description,
                )

            result[identity.to_zabbix()] = ResolvedMacro(
                identity=identity,
                value=resolved_value,
                description=description,
                macro_type=defn.macro_type,
            )
        return result


# ----- YAML loader -----


def read_property_macro_map(path: Union[str, Path]) -> PropertyMacroMapping:
    """Load and validate a Shape-B property-macro YAML mapping file."""
    try:
        with open(path) as f:
            data = yaml.load(f, Loader=_YamlLoader)
    except Exception as e:
        logger.error(
            "Failed to read property macro map file", file=str(path), error=str(e)
        )
        raise

    if data is None:
        return PropertyMacroMapping()

    try:
        file_in = MacroMapFileIn.model_validate(data)
    except Exception as e:
        logger.error("Invalid property macro map file", file=str(path), error=str(e))
        raise

    mapping = PropertyMacroMapping()
    seen: set[MacroIdentity] = set()

    def register(defn: MacroDefinition) -> None:
        if defn.identity in seen:
            logger.error(
                "Duplicate macro identity in mapping file; ignoring later occurrence",
                file=str(path),
                identity=defn.identity.to_zabbix(),
            )
            return
        seen.add(defn.identity)
        mapping.add(defn)

    for raw_name, macro_def in file_in.macros.items():
        try:
            name = fmt_macro_name(raw_name)
        except ValueError as e:
            logger.error(
                "Invalid macro name in mapping file; skipping",
                file=str(path),
                macro_name=raw_name,
                error=str(e),
            )
            continue

        if macro_def.properties:
            register(
                MacroDefinition(
                    identity=MacroIdentity(name=name),
                    description=macro_def.description,
                    macro_type=macro_def.type,
                    combine=macro_def.combine,
                    properties={
                        p: MacroValue(value=pv.value, description=pv.description)
                        for p, pv in macro_def.properties.items()
                    },
                )
            )

        for variant in macro_def.contexts:
            register(
                MacroDefinition(
                    identity=MacroIdentity(
                        name=name,
                        context=variant.context,
                        context_type=variant.context_type,
                    ),
                    description=variant.description or macro_def.description,
                    macro_type=macro_def.type,
                    combine=variant.combine,
                    properties={
                        p: MacroValue(value=pv.value, description=pv.description)
                        for p, pv in variant.properties.items()
                    },
                )
            )

    return mapping
