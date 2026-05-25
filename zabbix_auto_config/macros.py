from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from functools import cached_property
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Annotated
from typing import Any
from typing import NewType
from typing import Optional
from typing import TypedDict

import structlog.stdlib
import yaml
from pydantic import BaseModel
from pydantic import BeforeValidator
from pydantic import ConfigDict
from pydantic import Field
from pydantic import PrivateAttr
from pydantic import ValidationError
from pydantic import field_validator
from pydantic import model_validator
from typing_extensions import NamedTuple
from typing_extensions import Self
from typing_extensions import assert_never

from zabbix_auto_config.exceptions import EmptyMacroMappingError
from zabbix_auto_config.exceptions import InvalidMacroMappingFileError
from zabbix_auto_config.exceptions import MacroMappingFileNotFound
from zabbix_auto_config.exceptions import MacroMappingFileReadError

if TYPE_CHECKING:
    from zabbix_auto_config.config import Settings
    from zabbix_auto_config.models import Host
    from zabbix_auto_config.pyzabbix.types import Host as ZabbixHost
    from zabbix_auto_config.pyzabbix.types import Macro as ZabbixMacro

try:
    from yaml import CSafeLoader as _YamlLoader
except ImportError:
    from yaml import SafeLoader as _YamlLoader  # type: ignore[assignment]


logger = structlog.stdlib.get_logger(__name__)

MACRO_NAME_PATTERN = re.compile(r"^\{\$[A-Z0-9_.]+\}$")


MacroName = NewType("MacroName", str)
"""Validated and normalized macro name."""


MacroDescription = NewType("MacroDescription", str)
"""Correctly formatted macro description."""


def is_valid_macro_name(name: str) -> bool:
    """Check if the provided name is a valid Zabbix user macro name."""
    return bool(MACRO_NAME_PATTERN.match(name))


def validate_macro_name(macro: str) -> MacroName:
    """Normalize and validate a Zabbix user macro name."""
    macro = macro.strip()  # remove whitespace
    if not is_valid_macro_name(macro):
        raise ValueError(f"Invalid macro name {macro!r}")
    return MacroName(macro)


@lru_cache(maxsize=1000)
def is_valid_regexp(regex: str) -> bool:
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


class ResolveStrategy(str, Enum):
    """Strategy for resolving multiple property contributions to the same macro identity."""

    FIRST = "first"  # alphabetically first contributing property wins
    LAST = "last"  # alphabetically last contributing property wins
    REGEX = "regex"  # values join into (v1|v2|...), values can be regex patterns


class MacroValueType(str, Enum):
    """Zabbix usermacro value type (text/secret/vault)."""

    TEXT = "text"  # Zabbix usermacro type=0
    SECRET = "secret"  # type=1
    VAULT = "vault"  # type=2

    def to_zabbix(self) -> int:
        """Convert to the integer type that Zabbix expects."""
        if self.value == "text":
            return 0
        elif self.value == "secret":
            return 1
        elif self.value == "vault":
            return 2
        else:
            raise ValueError(f"Unknown macro value type: {self.value!r}")


class MacroKind(str, Enum):
    """Kind of macro: literal value or rendered template.

    Derived during parse from presence of `template:` field; not a YAML field.
    """

    PLAIN = "plain"
    TEMPLATE = "template"


@lru_cache(maxsize=1000)
def macro_to_zabbix(
    name: str,
    context: Optional[str] = None,
    context_type: ContextType = ContextType.STATIC,
) -> str:
    if context is None:
        return name
    base = name[:-1]  # strip trailing "}"
    ctx = context
    if context_type == ContextType.REGEX:
        escaped = ctx.replace('"', '\\"')
        return f'{base}:regex:"{escaped}"' + "}"
    if "}" in ctx or ctx.startswith('"'):
        escaped = ctx.replace('"', '\\"')
        return f'{base}:"{escaped}"' + "}"
    return f"{base}:{ctx}" + "}"


@dataclass(frozen=True)
class MacroIdentity:
    """Unique identity of a Zabbix user macro: (name, context, context_type)."""

    name: MacroName  # This NewType breaks mypy for test snapshots in <3.10 :(
    context: Optional[str] = None
    context_type: ContextType = ContextType.STATIC

    def to_zabbix(self) -> str:
        """Format as the macro string Zabbix expects (e.g. '{$M:"ctx"}').

        Adds context to macro if present.
        """
        return macro_to_zabbix(self.name, self.context, self.context_type)


def validate_template_macro_values(v: Any) -> dict[str, str]:
    """Coerce a dict of template macro values to string values."""
    if not isinstance(v, dict):
        raise ValueError("Expected a dict of template macro values")

    ret: dict[str, str] = {}
    for k, val in v.items():
        if not isinstance(val, (str, int, float)):
            raise ValueError(
                f"Template macro values must be scalar (str, int, float): {val!r}"
            )
        ret[str(k)] = str(val)
    return ret


TemplateMacroValues = Annotated[
    dict[str, str], BeforeValidator(validate_template_macro_values)
]


@dataclass
class MacroValue:
    """Value contribution from one property mapping."""

    value: Optional[str] = None
    description: Optional[str] = None
    values: TemplateMacroValues = field(default_factory=dict)
    template: Optional[str] = None  # per-property template override

    @classmethod
    def via_mapping(
        cls, mapping: dict[str, PropertyValueIn], parent_template: str | None
    ) -> dict[str, Self]:
        """Translate a PropertyValueIn mapping to a mapping of MacroValue objects.

        Maintains the keys used in the original mapping (be that property or host names).
        """
        return {
            p: cls(
                value=pv.value,
                description=pv.description,
                values={k: str(v) for k, v in pv.values.items()},
                template=pv.template
                or parent_template,  # inherit from parent macro if not set
            )
            for p, pv in mapping.items()
        }


@dataclass
class MacroDefinition:
    """All metadata for one macro identity, plus its property->value table.

    Context-data is stored in the macro's `identity` field.
    """

    identity: MacroIdentity
    description: Optional[str] = None
    value_type: MacroValueType = MacroValueType.TEXT
    resolve: ResolveStrategy = ResolveStrategy.FIRST
    template: Optional[str] = None
    defaults: TemplateMacroValues = field(default_factory=dict)
    properties: dict[str, MacroValue] = field(default_factory=dict)
    hosts: dict[str, MacroValue] = field(default_factory=dict)  # per-host overrides

    @property
    def macro(self) -> str:
        return self.identity.to_zabbix()

    @property
    def kind(self) -> MacroKind:
        return MacroKind.TEMPLATE if self.template is not None else MacroKind.PLAIN

    @cached_property
    def host_patterns(self) -> list[tuple[re.Pattern[str], str]]:
        """Compiled host regex patterns, sorted longest-first then alphabetical.

        Iterated only after exact dict lookup on `hosts` misses. Compiled
        lazily on first access; not serialized.
        """
        patterns: list[tuple[re.Pattern[str], str]] = []
        for name in self.hosts:
            try:
                patterns.append((re.compile(name), name))
            except re.error:
                continue
        patterns.sort(key=lambda p: (-len(p[1]), p[1]))
        return patterns


@dataclass
class ResolvedMacro:
    """A macro resolved for a specific host's property set."""

    identity: MacroIdentity
    value: str
    description: Optional[MacroDescription] = None
    value_type: MacroValueType = MacroValueType.TEXT

    @property
    def macro(self) -> str:
        return self.identity.to_zabbix()


# ----- Pydantic input models (YAML schema) -----


class PropertyValueIn(BaseModel):
    """Per-property value entry. Accepts scalar shorthand or expanded form."""

    # Used by plain macros
    value: Optional[str] = None
    # Used by templates
    values: TemplateMacroValues = Field(default_factory=dict)  # for overriden template
    description: Optional[str] = None
    template: Optional[str] = None

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def _coerce_scalar(cls, data: Any) -> Any:
        """Coerce a single scalar value to the expanded form with a 'value' key.

        Allows property values to be defined as a single value or as
        a mapping with additional metadata like description."""
        if isinstance(data, (str, int, float, bool)):
            return {"value": str(data)}
        elif data is None:
            return {"value": None}
        return data


_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def get_placeholders(template: str) -> set[str]:
    """Extract the set of placeholders used in a template string."""
    return set(_PLACEHOLDER_RE.findall(template))


def get_substitutions(
    defn: MacroDefinition, val: MacroValue, facts: HostFacts, prop: str
) -> dict[str, str]:
    """Get subtitutions used to render a template for a macro value."""
    subs: TemplateMacroValues = {k: str(v) for k, v in facts.items()}
    # NOTE: must inject defaults, otherwise templates may fail to render!
    #       why doesn't the validator ensure these values exist in values?
    subs.update(defn.defaults)
    subs.update(val.values)  # overrides defaults
    subs.update({"property": prop})
    return subs


def _apply_template(
    template: str, subs: TemplateMacroValues, identity: MacroIdentity
) -> str:
    """Substitute `{{key}}` placeholders in template using subs."""

    def _replace(m: re.Match[str]) -> str:
        key = m.group(1)
        if key in subs:
            return subs[key]
        logger.warning(
            "Unknown template placeholder; leaving as-is",
            macro=identity.to_zabbix(),
            placeholder=key,
        )
        return m.group(0)

    return _PLACEHOLDER_RE.sub(_replace, template)


def _validate_template_entries(
    template: Optional[str],
    defaults: TemplateMacroValues,
    entries: dict[str, PropertyValueIn],
    label: str,
) -> None:
    """Validate template/defaults/entries consistency for one entry kind.

    `label` is the singular noun used in error messages ("Property" / "Host").
    Plural is constructed by appending "ies" / "s" via simple substitution where needed.
    """
    label_plural = "Properties" if label == "Property" else label + "s"

    # Detect if values are defined on macro with no template
    if template is None:
        # HACK: recurse here to validate child templates.
        # Detect entries defining templates when parent does not
        has_template = [p for p, pv in entries.items() if pv.template is not None]
        if has_template:
            raise ValueError(
                f"{label_plural} {sorted(has_template)} define templates but macro definition does not"
            )

        # Check for entries without `template` and `value`
        missing = [
            p for p, pv in entries.items() if pv.value is None and pv.template is None
        ]
        if missing:
            raise ValueError(f"{label} values cannot be null: {sorted(missing)}")

        with_values = {
            p: list(pv.values)
            for p, pv in entries.items()
            if pv.values and not pv.template
        }
        if with_values:
            raise ValueError(
                f"{label_plural} have `values` keys but no template defined: {with_values}"
            )
        return

    # check for values on entries, and detect collisions with reserved host fact keys
    for p, pv in entries.items():
        if pv.value is not None:
            raise ValueError(
                f"{label} {p!r} uses scalar shorthand; not allowed with template"
            )
        bad_values = sorted(k for k in pv.values if k in BUILTIN_PLACEHOLDERS)
        if bad_values:
            raise ValueError(
                f"{label} {p!r} template values collide with builtin placeholders: {bad_values}"
            )

    # Detect placeholders with no defaults for entries
    missing_per_entry: dict[str, list[str]] = {}
    for p, pv in entries.items():
        # FIXME: the problem here is that we have `template` and `pv.template`
        # and it's not clear which one will be used to resolve the template,
        # since the actual resolution doesn't happen here.
        # Tests show no difference when using `template` and `pv.template or template`
        # but that's not a reason to not remove this ambiguity
        placeholders = get_placeholders(pv.template or template)
        resolved = set(defaults) | set(pv.values) | BUILTIN_PLACEHOLDERS
        missing = sorted(placeholders - resolved)
        if missing:
            missing_per_entry[p] = missing
    if missing_per_entry:
        raise ValueError(f"Template placeholders not satisfied: {missing_per_entry}")

    # Validate entries with their own template recursively
    for p, pv in entries.items():  # noqa: B007
        if pv.template is not None:
            # HACK: some unfortunate recursion here - should refactor
            _validate_template_entries(
                template=pv.template,
                defaults=pv.values,  # values instead of defaults
                entries={},  # nested entries can't have nested entries
                label=label,
            )


def _validate_template_props(
    template: Optional[str],
    defaults: TemplateMacroValues,
    properties: dict[str, PropertyValueIn],
    hosts: Optional[dict[str, PropertyValueIn]] = None,
) -> None:
    """Validate template/defaults/properties/hosts consistency.

    Raises ValueError if validation fails.

    NOTE: this function should only be called when reading from the mapping file.
    We do not want to raise exceptions when resolving macros for hosts!
    """
    hosts = hosts or {}

    if template is None and defaults:
        raise ValueError("'defaults' set but no 'template' defined")

    if template is not None:
        bad_defaults = sorted(k for k in defaults if k in BUILTIN_PLACEHOLDERS)
        if bad_defaults:
            raise ValueError(
                f"'defaults' keys collide with builtin placeholders: {bad_defaults}"
            )

    _validate_template_entries(template, defaults, properties, label="Property")
    if hosts:
        _validate_template_entries(template, defaults, hosts, label="Host")
        for hostname in hosts:
            if not is_valid_regexp(hostname):
                raise ValueError(f"Invalid host pattern: {hostname!r}")


def _inject_template_into_entries(
    entries: Any, template: str, defaults: dict[str, Any]
) -> None:
    """Inject template (if missing) and defaults (into `values`) for each entry.

    Used for `properties` and `hosts` blocks (top-level and per-context).
    Operates in-place. No-op for unexpected types.
    """
    if not isinstance(entries, dict):
        return
    # TODO: if values are None, we should add an empty dict!
    # The current .values() approach does not work for this!
    # we need to assign a dict to the key during iteration.
    for val in entries.values():  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(val, dict):
            continue
        if not val.get("template"):
            val["template"] = template
        if not val.get("values"):
            val["values"] = {}
        if isinstance(val["values"], dict):
            for k, v in defaults.items():
                val["values"].setdefault(k, v)


class MacroContextIn(BaseModel):
    """Macro context from mapping file."""

    context: str
    context_type: ContextType = ContextType.STATIC
    description: Optional[str] = None
    template: Optional[str] = None
    defaults: TemplateMacroValues = Field(default_factory=dict)
    properties: dict[str, PropertyValueIn] = Field(default_factory=dict)
    hosts: dict[str, PropertyValueIn] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.context_type == ContextType.REGEX and not is_valid_regexp(self.context):
            raise ValueError(f"Invalid regex context: {self.context!r}")
        _validate_template_props(
            self.template, self.defaults, self.properties, self.hosts
        )
        return self


HostValuesIn = dict[str, str]  # May add validator to this


class MacroDefIn(BaseModel):
    """Top-level macro definition entry from mapping file."""

    description: Optional[str] = None
    value_type: MacroValueType = MacroValueType.TEXT
    resolve: ResolveStrategy = ResolveStrategy.FIRST
    template: Optional[str] = None
    defaults: TemplateMacroValues = Field(default_factory=dict)
    properties: dict[str, PropertyValueIn] = Field(default_factory=dict)
    contexts: list[MacroContextIn] = Field(default_factory=list)
    hosts: dict[str, PropertyValueIn] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _inject_template_to_contexts_and_properties(cls, data: Any) -> Any:
        """Inject top-level template and defaults to contexts/properties/hosts if missing."""
        # NOTE: This is hacky and overly dynamic for my tastes.
        # We have to perform this mutation before proper model validation, because
        # MacroContextIn calls _validate_template_props in its own validator,
        # which requires template and defaults/values to be present.
        #
        # Furthermore, each context is more or less its own macro definition,
        # which means we have to inject it not only into the top-level properties
        # and hosts, but also into each context's properties and hosts.
        if not isinstance(data, dict):
            return data  # pragma: no cover # pydantic error

        template = data.get("template")
        if not template or not isinstance(template, str):
            return data  # nothing to do

        defaults = data.get("defaults", {})
        if not isinstance(defaults, dict):
            return data  # pragma: no cover # pydantic error

        # Inject into top-level properties and hosts
        _inject_template_into_entries(data.get("properties", {}), template, defaults)
        _inject_template_into_entries(data.get("hosts", {}), template, defaults)

        # Inject into contexts (template, defaults, then per-context properties/hosts)
        contexts = data.get("contexts", [])
        if isinstance(contexts, list):
            for ctx in contexts:
                if not isinstance(ctx, dict):
                    continue
                # Inject template if missing
                if not ctx.get("template"):
                    ctx["template"] = template

                # Inject defaults
                if not ctx.get("defaults"):
                    ctx["defaults"] = defaults
                if isinstance(ctx["defaults"], dict):
                    for k, v in defaults.items():
                        ctx["defaults"].setdefault(k, v)

                ctx_template = ctx.get("template")
                ctx_defaults = ctx.get("defaults", {})

                # Inject defaults into properties and hosts for this context
                # NOTE: should we do a check for empty template/context before injecting?
                if isinstance(ctx_template, str) and isinstance(ctx_defaults, dict):
                    _inject_template_into_entries(
                        ctx.get("properties", {}), ctx_template, ctx_defaults
                    )
                    _inject_template_into_entries(
                        ctx.get("hosts", {}), ctx_template, ctx_defaults
                    )
        return data

    @model_validator(mode="after")
    def _validate_template(self) -> Self:
        if self.template is not None and self.resolve == ResolveStrategy.REGEX:
            raise ValueError("template macros do not support resolve=regex")
        for v in self.contexts:
            # NOTE: Should we actually forbid using regex resolution for contexts
            # with templates? There's no technical reason to do so!
            # It's only forbidden because the main use case for templates is
            # rendering URLs with host facts, but that is not the _only_ use case.
            # We should not be so opinionated!
            if v.template is not None and self.resolve == ResolveStrategy.REGEX:
                raise ValueError(
                    f"context variant {v.context!r} uses template; "
                    "parent must not use resolve=regex"
                )
        _validate_template_props(
            self.template, self.defaults, self.properties, self.hosts
        )
        return self


class MacroMapFileIn(BaseModel):
    """Top-level YAML schema for property-macro mapping files.

    Used for input validation of the property:macro mapping YAML file.
    """

    macros: dict[MacroName, MacroDefIn] = Field(default_factory=dict)
    """Mapping of all loaded macro definitions from the mapping file."""

    @field_validator("macros", mode="before")
    @classmethod
    def _none_is_empty_macrodef(cls, v: Any) -> Any:
        """Null value for a macro is an empty definition.

        Allows short-hand notation for macro without properties,
        marking it as 'managed', removing it from every host in Zabbix.
        I.e.:

        ```yaml
        macros:
          "{$WILL_BE_REMOVED}":
        ```
        is equivalent to:

        ```yaml
        macros:
          "{$WILL_BE_REMOVED}":
            properties: {}
        """
        if not isinstance(v, dict):
            return v  # pragma: no cover # pydantic error
        for k, values in v.items():
            if values is None:
                v[k] = MacroDefIn()
        return v

    @field_validator("macros", mode="before")
    @classmethod
    def _validate_macro_names(cls, macros: Any) -> dict[MacroName, MacroDefIn]:
        """Validate and normalize macro names."""
        if not isinstance(macros, dict):
            return macros  # pragma: no cover # pydantic error

        for raw_name, val in list(macros.items()):
            try:
                macro_name = validate_macro_name(raw_name)
            except ValueError as e:
                logger.error(
                    "Invalid macro name in mapping file; skipping",
                    macro_name=raw_name,
                    error=str(e),
                )
                del macros[raw_name]
            else:
                if macro_name != raw_name:
                    logger.warning(
                        "Macro name has leading/trailing whitespace; normalizing",
                        original=raw_name,
                        normalized=macro_name,
                    )
                    macros[macro_name] = val
                    del macros[raw_name]
        return macros

    @classmethod
    def load(cls, path: Path) -> Self:
        """Load a MacroMapFileIn from a file path."""
        try:
            with open(path) as f:
                data = yaml.load(f, Loader=_YamlLoader)
        except FileNotFoundError as e:
            raise MacroMappingFileNotFound(
                f"Macro mapping file {path} not found: {e}"
            ) from e
        except Exception as e:
            raise MacroMappingFileReadError(
                f"Failed to read macro map file {path}: {e}"
            ) from e

        if data is None:  # NOTE: why not {}, "" and other empty data?
            raise EmptyMacroMappingError("Macro map file is empty")

        try:
            file_in = cls.model_validate(data)
        except ValidationError:  # re-raise as-is
            raise
        except Exception as e:
            raise InvalidMacroMappingFileError(
                f"Invalid macro map file {path}: {e}"
            ) from e
        return file_in


# ----- Property-to-macro mapping (resolved, public API) -----


class HostFacts(TypedDict):
    """Facts about the hosts to construct macros for.

    Used to provide values for templates.
    """

    hostname: str
    # future: proxy: NotRequired[str], etc.


_HOST_FACT_PLACEHOLDERS = frozenset(HostFacts.__annotations__)  # injected by host facts
_INJECTED_PLACEHOLDERS = frozenset[str]({"property"})  # injected after macro resolution
BUILTIN_PLACEHOLDERS = _HOST_FACT_PLACEHOLDERS | _INJECTED_PLACEHOLDERS
"""Keys that cannot be redefined in macro values/defaults."""


def get_host_facts(host: Host) -> HostFacts:
    """Extract host facts from a Host model instance for use in template macros."""
    return {
        "hostname": host.hostname,
        # future: "proxy": host.proxy_pattern, etc.
    }


class HostMacroResult(NamedTuple):
    """Result of resolving macros for a host, keyed by macro identity."""

    add: dict[str, ResolvedMacro]
    """Macros to add to the host, keyed by macro identity."""

    update: dict[str, tuple[ZabbixMacro, ResolvedMacro]]
    """Macros to update on the host, keyed by macro identity."""

    remove: dict[str, ZabbixMacro]
    """Macros to remove from the host, keyed by macro identity."""


class PropertyMacroMapping(BaseModel):
    """All macro definitions, indexed by the property names that contribute to them."""

    # NOTE: rewrite as property? let _by_property be the single source of truth
    # Either accept recalculation overhead, or cache and invalidate on add() call
    definitions: list[MacroDefinition] = Field(default_factory=list)
    """List of all macro definitions."""

    description_prefix: Optional[str] = None
    """Prefix to append to descriptions of all macros derived from this mapping, to provide context in Zabbix UI."""

    _by_property: dict[str, list[MacroDefinition]] = PrivateAttr(
        default_factory=lambda: defaultdict(list)
    )
    """Macros indexed by properties that contribute to them.

    This mapping is populated manually as definitions are added. This is not
    ideal, as it opens up for inconsistency between the list of macros
    and the index, but it is necessary to have efficient lookup by name
    when dealing with thousands of hosts.
    """

    _host_bearing: list[MacroDefinition] = PrivateAttr(default_factory=list)
    """Definitions that have at least one entry in `hosts`.

    Shortcut for iterating over macros with host overrides, so we can resolve
    them separately from property-derived macros.
    """

    _managed_macros: set[str] = PrivateAttr(default_factory=set)
    """Identities of all macros managed by the macro mapping."""

    @property
    def managed_macros(self) -> set[str]:
        """Identities of all macros managed by the macro mapping."""
        return self._managed_macros

    @classmethod
    def from_config(cls, config: Settings) -> Self:
        """Alternate constructor for deriving the mapping file settings from config."""
        return cls.load(
            config.zabbix.macro_map_file,
            description_prefix=config.zabbix.macro_description_prefix,
        )

    @classmethod
    def _load_infile(cls, path: Path) -> MacroMapFileIn:
        """Attempt to load a macro mapping input file."""
        return MacroMapFileIn.load(path)

    @classmethod
    def load(cls, path: Path, description_prefix: Optional[str] = None) -> Self:
        """Load and validate a property:macro YAML mapping file."""
        mapping = cls(description_prefix=description_prefix)

        try:
            file_in = cls._load_infile(path)
        except MacroMappingFileNotFound:
            logger.warning(
                "Property macro map file does not exist; using empty mapping",
                file=str(path),
            )
            return mapping
        except InvalidMacroMappingFileError as e:
            logger.error(
                "Invalid property macro map file", file=str(path), error=str(e)
            )
            raise
        except Exception as e:
            logger.error(
                "Failed to read property macro map file", file=str(path), error=str(e)
            )
            raise

        seen: set[MacroIdentity] = set()

        def register(defn: MacroDefinition) -> None:
            # NOTE: duplicate def error will likely not ever be emitted
            # because pyyaml silently overwrites duplicate mapping keys on read!
            if defn.identity in seen:
                logger.error(  # pragma: no cover
                    "Duplicate macro identity in mapping file; ignoring later occurrence",
                    file=str(path),
                    identity=defn.identity.to_zabbix(),
                )
                return  # pragma: no cover
            seen.add(defn.identity)
            mapping.add(defn)

        for name, macro_def in file_in.macros.items():
            # Register macro
            if not macro_def.properties and not macro_def.hosts:
                logger.warning(
                    "Macro definition has no properties or hosts. Will be used for removal only.",
                    macro_name=name,
                )
            register(
                MacroDefinition(
                    identity=MacroIdentity(name=name),
                    description=macro_def.description,
                    value_type=macro_def.value_type,
                    resolve=macro_def.resolve,
                    template=macro_def.template,
                    defaults=dict(macro_def.defaults),
                    properties=MacroValue.via_mapping(
                        macro_def.properties, macro_def.template
                    ),
                    hosts=MacroValue.via_mapping(macro_def.hosts, macro_def.template),
                )
            )

            # Register macro variants with contexts
            for variant in macro_def.contexts:
                if not variant.properties and not variant.hosts:
                    logger.warning(
                        "Macro context variant has no properties or hosts. Will be used for removal only.",
                        macro_name=name,
                        context=variant.context,
                    )
                variant_template = variant.template or macro_def.template
                register(
                    MacroDefinition(
                        identity=MacroIdentity(
                            name=name,
                            context=variant.context,
                            context_type=variant.context_type,
                        ),
                        description=variant.description or macro_def.description,
                        value_type=macro_def.value_type,  # inherit from parent macro
                        resolve=macro_def.resolve,  # inherit from parent macro
                        template=variant_template,
                        defaults=dict(variant.defaults),
                        properties=MacroValue.via_mapping(
                            variant.properties, variant_template
                        ),
                        hosts=MacroValue.via_mapping(variant.hosts, variant_template),
                    )
                )

        return mapping

    def add(self, definition: MacroDefinition) -> None:
        """Add a macro definition to the mapping."""
        # NOTE: this feels like a code smell: we update 4 different data structures
        # on each add. There are no defined constraints that prevent inconsistencies
        # between them. Don't even get me started on a potential `remove()` method...
        #
        # We need a single source of truth that we derive these alternate
        # datastructures from when accessed via some caching mechanism.
        # Their reason d'etre is to provide efficient lookups for:
        # - definitions by property (for resolving macros for hosts)
        # - definitions with host overrides (for resolving host-specific macros)
        # - identities of managed macros (for pruning old macros from hosts)
        self.definitions.append(definition)
        for prop in definition.properties:
            self._by_property[prop].append(definition)
        if definition.hosts:
            self._host_bearing.append(definition)
        self._managed_macros.add(definition.macro)

    def _get_description(self, description: str | None) -> Optional[MacroDescription]:
        """Get final description for a macro, with mapping-level prefix if defined."""
        parts: list[str] = []
        if self.description_prefix:
            parts.append(self.description_prefix.strip())
        if description:
            parts.append(description.strip())
        if parts:  # avoid creating empty description if no parts -> "" semantically different from None
            return MacroDescription(" ".join(parts))

    def get_macros(
        self,
        properties: Iterable[str],
        host_facts: HostFacts,
    ) -> dict[str, ResolvedMacro]:
        """Resolve final macros for the given property set.

        Returned dict is keyed by the Zabbix macro string (including context).
        """
        # Mapping of macro identity to its definition and all contributing property->value pairs
        per_identity: dict[
            MacroIdentity, tuple[MacroDefinition, list[tuple[str, MacroValue]]]
        ] = {}

        # The property dedup code is overkill in practice!
        # In tests, we call this method with a list of properties
        # but in the actual ZAC code, we always pass in a set of properties
        # making the deduplication part of this loop redundant.
        # However, in order to ensure ordering in tests, it's very useful
        # for this method to be able to take in lists... So we keep the dedup code.

        # Get macros associated with each property
        seen_props: set[str] = set()
        for prop in properties:
            if prop in seen_props:  # ignore repeated properties
                continue
            seen_props.add(prop)
            for defn in self._by_property.get(prop, []):
                macro_value = defn.properties.get(prop)
                if macro_value is None:
                    continue
                slot = per_identity.setdefault(defn.identity, (defn, []))
                slot[1].append((prop, macro_value))

        # Resolve macros by host overrides
        #
        # Host match always wins: replaces any property-derived
        # contributions and bypasses the resolve strategy.
        # Maps identity -> (matched_key, MacroValue) for the resolution loop below.
        host_overrides: dict[MacroIdentity, tuple[str, MacroValue]] = {}
        hostname = host_facts["hostname"]
        for defn in self._host_bearing:
            mv = defn.hosts.get(hostname)
            matched_key = hostname
            if mv is None:
                for pattern, key in defn.host_patterns:
                    if pattern.fullmatch(hostname):
                        mv = defn.hosts[key]
                        matched_key = key
                        break
            if mv is not None:
                host_overrides[defn.identity] = (matched_key, mv)
                # Ensure a slot exists so the resolution loop visits this identity
                # even if no property contributed.
                per_identity.setdefault(defn.identity, (defn, []))

        # Resolve macro values by properties
        result: dict[str, ResolvedMacro] = {}
        for identity, (defn, contributions) in per_identity.items():
            # Only resolve property contribution if no host override exists!
            override = host_overrides.get(identity)
            if override is not None:
                matched_key, macro_value = override
                template = macro_value.template or defn.template
                if template is not None:
                    subs = get_substitutions(defn, macro_value, host_facts, matched_key)
                    resolved_value = _apply_template(template, subs, identity)
                else:
                    resolved_value = macro_value.value or ""
                result[identity.to_zabbix()] = ResolvedMacro(
                    identity=identity,
                    value=resolved_value,
                    description=self._get_description(
                        macro_value.description or defn.description
                    ),
                    value_type=defn.value_type,
                )
                continue

            if not contributions:  # safety for 0-indexing
                continue

            # NOTE: the two different sorting calls within each strategy branch are a
            # code smell, but we need to deduplicate values for resolve=regex,
            # which would break the sorting order if we sorted before deduplication.

            if defn.resolve in (ResolveStrategy.FIRST, ResolveStrategy.LAST):
                contributions.sort(key=lambda c: c[0])

                pick_idx = 0 if defn.resolve == ResolveStrategy.FIRST else -1
                winning_prop, macro_value = contributions[pick_idx]
                if len(contributions) > 1:
                    logger.debug(
                        "Multiple contributing properties for macro; resolved to single value",
                        macro=identity.to_zabbix(),
                        resolve=defn.resolve.value,
                        winning_property=winning_prop,
                        ignored_properties=[
                            c[0] for c in contributions if c[0] != winning_prop
                        ],
                    )

                # FIXME: Template rendering logic is contained within this
                # block, which means we do not support template rendering
                # for regex-resolved macro values. Even if we allow it in
                # the main validators, we will only ever render the values here!
                # Bug waiting to happen; should be generalized
                template = macro_value.template or defn.template
                if template is not None:
                    subs = get_substitutions(
                        defn, macro_value, host_facts, winning_prop
                    )
                    resolved_value = _apply_template(template, subs, identity)
                else:
                    resolved_value = macro_value.value or ""
                description = macro_value.description or defn.description
            elif defn.resolve == ResolveStrategy.REGEX:  # resolve: regex
                # Deduplicate values (validator guarantees no None values for regex) NOTE: is this true???
                values = sorted(
                    {mv.value for _, mv in contributions if mv.value is not None}
                )
                if not values:
                    continue
                resolved_value = (
                    f"({'|'.join(values)})" if len(values) > 1 else values[0]
                )
                if not is_valid_regexp(resolved_value):
                    logger.error(
                        "Resolved regex macro is invalid; skipping",
                        macro=identity.to_zabbix(),
                        value=resolved_value,
                    )
                    continue

                # Use first valid description from contributions + defn
                description = next(
                    (mv.description for _, mv in contributions if mv.description),
                    defn.description,
                )
            else:
                # Let type checker catch unhandled strategies
                assert_never(defn.resolve)

            # TODO: key by MacroName here
            # but we can't do that right now, because MacroName exists to validate
            # macro names from the config file, not the final macro names where
            # context may exist. Sigh...
            result[identity.to_zabbix()] = ResolvedMacro(
                identity=identity,
                value=resolved_value,
                description=self._get_description(description),
                value_type=defn.value_type,
            )
        return result

    def resolve_macros(
        self,
        db_host: Host,
        zabbix_host: ZabbixHost,
    ) -> HostMacroResult:
        """Resolve macros for the given host

        Returns a HostMacroResult containing macros to keep, add/update, and remove.
        """
        # Only include managed macros (macros on host that are also defined in the mapping)
        current_macros = {
            macro.macro: macro
            for macro in zabbix_host.macros
            if macro.macro in self.managed_macros
        }

        # Resolve macros for host given its properties + facts
        facts = get_host_facts(db_host)
        resolved_macros = self.get_macros(db_host.properties, facts)

        # Determine macros to remove
        # Remove macros that are managed, but not connected to any current properties
        to_remove: dict[str, ZabbixMacro] = {}
        for macro in set(current_macros) - set(resolved_macros):
            to_remove[macro] = current_macros[macro]

        # Add macros connected to host's properties that it doesn't already have
        to_add: dict[str, ResolvedMacro] = {}
        for macro in set(resolved_macros) - set(current_macros):
            to_add[macro] = resolved_macros[macro]

        # Determine macros to update (compare differences)
        # Update macros whose values or descriptions have changed
        to_update: dict[str, tuple[ZabbixMacro, ResolvedMacro]] = {}
        for macro_name in set(resolved_macros).intersection(set(current_macros)):
            # Direct key access for speed (+ it's safe enough due to intersection above)
            current_macro = current_macros[macro_name]
            resolved_macro = resolved_macros[macro_name]
            if (
                resolved_macro.value != current_macro.value
                or resolved_macro.description != current_macro.description
                or resolved_macro.value_type.to_zabbix() != current_macro.type
            ):
                to_update[macro_name] = (current_macro, resolved_macro)

        return HostMacroResult(
            add=to_add,
            update=to_update,
            remove=to_remove,
        )
