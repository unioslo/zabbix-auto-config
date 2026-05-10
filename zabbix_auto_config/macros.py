from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Annotated
from typing import Any
from typing import Optional
from typing import TypedDict
from typing import Union

import structlog.stdlib
import yaml
from pydantic import BaseModel
from pydantic import BeforeValidator
from pydantic import ConfigDict
from pydantic import Field
from pydantic import PrivateAttr
from pydantic import field_validator
from pydantic import model_validator
from typing_extensions import Self

try:
    from yaml import CSafeLoader as _YamlLoader
except ImportError:
    from yaml import SafeLoader as _YamlLoader  # type: ignore[assignment]

if TYPE_CHECKING:
    from zabbix_auto_config.models import Host

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
    extras: TemplateMacroValues = field(default_factory=dict)


@dataclass
class MacroDefinition:
    """All metadata for one macro identity, plus its property->value table."""

    identity: MacroIdentity
    description: Optional[str] = None
    value_type: MacroValueType = MacroValueType.TEXT
    resolve: ResolveStrategy = ResolveStrategy.FIRST
    template: Optional[str] = None
    defaults: TemplateMacroValues = field(default_factory=dict)
    properties: dict[str, MacroValue] = field(default_factory=dict)

    @property
    def macro(self) -> str:
        return self.identity.to_zabbix()

    @property
    def kind(self) -> MacroKind:
        return MacroKind.TEMPLATE if self.template is not None else MacroKind.PLAIN


@dataclass
class ResolvedMacro:
    """A macro resolved for a specific host's property set."""

    identity: MacroIdentity
    value: str
    description: Optional[str] = None
    value_type: MacroValueType = MacroValueType.TEXT

    @property
    def macro(self) -> str:
        return self.identity.to_zabbix()


# ----- Pydantic input models (YAML schema) -----


class PropertyValueIn(BaseModel):
    """Per-property value entry. Accepts scalar shorthand or expanded form."""

    value: Optional[str] = None
    description: Optional[str] = None

    model_config = ConfigDict(extra="allow")

    def get_extra_values(self) -> dict[str, Any]:
        """Get the dict of values to be used for macro resolution."""
        return self.model_extra or {}

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


def _validate_template_props(
    template: Optional[str],
    defaults: TemplateMacroValues,
    properties: dict[str, PropertyValueIn],
) -> None:
    """Validate template/defaults/properties consistency.

    Raises ValueError if validation fails.

    NOTE: this function should only be called when reading from the mapping file.
    We do not want to raise exceptions when resolving macros for hosts!
    """
    # Detect if values are defined on macro with no template
    if template is None:
        if defaults:
            raise ValueError("'defaults' set but no 'template' defined")
        missing = [p for p, pv in properties.items() if pv.value is None]
        if missing:
            raise ValueError(
                f"Properties missing value (no template defined): {missing}"
            )
        with_extras = {
            p: list(pv.get_extra_values())
            for p, pv in properties.items()
            if pv.model_extra  # leaking abstraction here... alternative is calling pv.get_extra_values() twice
        }
        if with_extras:
            raise ValueError(
                f"Properties have extra keys but no template defined: {with_extras}"
            )
        return

    # Detect collisions with reserved keys
    bad_defaults = sorted(k for k in defaults if k in RESERVED_HOST_FACT_KEYS)
    if bad_defaults:
        raise ValueError(
            f"'defaults' keys collide with reserved host facts: {bad_defaults}"
        )
    for p, pv in properties.items():
        if pv.value is not None:
            raise ValueError(
                f"Property {p!r} uses scalar shorthand; not allowed with template"
            )
        bad_extras = sorted(
            k for k in pv.get_extra_values() if k in RESERVED_HOST_FACT_KEYS
        )
        if bad_extras:
            raise ValueError(
                f"Property {p!r} extras collide with reserved host facts: {bad_extras}"
            )

    # Detect placeholders with no defaults
    placeholders = set(_PLACEHOLDER_RE.findall(template))
    missing_per_prop: dict[str, list[str]] = {}
    for p, pv in properties.items():
        resolved = set(defaults) | set(pv.get_extra_values()) | RESERVED_HOST_FACT_KEYS
        missing = sorted(placeholders - resolved)
        if missing:
            missing_per_prop[p] = missing
    if missing_per_prop:
        raise ValueError(f"Template placeholders not satisfied: {missing_per_prop}")


class MacroContextIn(BaseModel):
    """Macro context from mapping file."""

    context: str
    context_type: ContextType = ContextType.STATIC
    description: Optional[str] = None
    template: Optional[str] = None
    defaults: TemplateMacroValues = Field(default_factory=dict)
    properties: dict[str, PropertyValueIn] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.context_type == ContextType.REGEX and not validate_regexp(self.context):
            raise ValueError(f"Invalid regex context: {self.context!r}")
        _validate_template_props(self.template, self.defaults, self.properties)
        return self


class MacroDefIn(BaseModel):
    """Top-level macro definition entry from mapping file."""

    description: Optional[str] = None
    value_type: MacroValueType = MacroValueType.TEXT
    resolve: ResolveStrategy = ResolveStrategy.FIRST
    template: Optional[str] = None
    defaults: TemplateMacroValues = Field(default_factory=dict)
    properties: dict[str, PropertyValueIn] = Field(default_factory=dict)
    contexts: list[MacroContextIn] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _inject_template_to_contexts(cls, data: Any) -> Any:
        """Inject top-level template and defaults to contexts if missing."""
        # NOTE: this is kinda hacky, and we only have to do this because
        # MacroContextIn calls _validate_template_props in its own validator,
        # which requires the template to be present in the instance.
        #
        # We could refactor the validation to only be called once after all
        # definitions have been fully constructed - instead of on a per-model basis.
        if not isinstance(data, dict):
            return data  # pydantic will handle the error
        template = data.get("template")
        contexts = data.get("contexts", [])
        if template and isinstance(contexts, list):
            defaults = data.get("defaults", {})
            for ctx in contexts:
                if isinstance(ctx, dict):
                    # Inject template if missing
                    if not ctx.get("template"):
                        ctx["template"] = template

                    # Inject defaults
                    if not ctx.get("defaults"):
                        ctx["defaults"] = defaults
                    elif isinstance(ctx["defaults"], dict):
                        # Some defaults missing
                        for k, v in defaults.items():
                            ctx["defaults"].setdefault(k, v)
                    # Fall through if defaults is not a dict
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
        _validate_template_props(self.template, self.defaults, self.properties)
        return self


class MacroMapFileIn(BaseModel):
    """Top-level YAML schema for property-macro mapping files.

    Used for input validation of the property:macro mapping YAML file.
    """

    macros: dict[str, MacroDefIn] = Field(default_factory=dict)

    @field_validator("macros")
    @classmethod
    def _validate_macro_keys(cls, v: dict[str, MacroDefIn]) -> dict[str, MacroDefIn]:
        for name in v:
            if not is_valid_macro_name(name):
                raise ValueError(f"Invalid macro name key: {name!r}")
        return v


# ----- Property-to-macro mapping (resolved, public API) -----


class HostFacts(TypedDict):
    """Facts about the hosts to construct macros for.

    Used to provide values for templates.
    """

    hostname: str
    # future: proxy: NotRequired[str], etc.


RESERVED_HOST_FACT_KEYS = frozenset(HostFacts.__annotations__)


def get_host_facts(host: Host) -> HostFacts:
    """Extract host facts from a Host model instance for use in template macros."""
    return {
        "hostname": host.hostname,
        # future: "proxy": host.proxy_pattern, etc.
    }


class PropertyMacroMapping(BaseModel):
    """All macro definitions, indexed by the property names that contribute to them."""

    # TODO: remove this list!! It's unused!
    definitions: list[MacroDefinition] = Field(default_factory=list)
    """List of all macro definitions."""

    _by_property: dict[str, list[MacroDefinition]] = PrivateAttr(
        default_factory=lambda: defaultdict(list)
    )
    """Macros indexed by properties that contribute to them.

    This mapping is populated manually as definitions are added. It is not
    ideal, as it opens up for inconsistency between the list of macros
    and the index, but it is necessary to have efficient lookup by name
    when dealing with thousands of hosts.
    """

    def add(self, definition: MacroDefinition) -> None:
        self.definitions.append(definition)
        for prop in definition.properties:
            self._by_property[prop].append(definition)

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
            if not contributions:  # safety
                continue

            # NOTE: the two different sorting calls within each if-branch are a
            # code smell, but we need to deduplicate values for resolve=regex,
            # which would break the sorting order if we sorted before deduplication.

            if defn.resolve in (ResolveStrategy.FIRST, ResolveStrategy.LAST):
                if defn.template is not None:
                    contributions.sort(key=lambda c: c[0])
                else:
                    contributions.sort(key=lambda c: c[1].value or "")
                pick_idx = 0 if defn.resolve == ResolveStrategy.FIRST else -1
                winning_prop, mv = contributions[pick_idx]
                if len(contributions) > 1:
                    logger.warning(
                        "Multiple contributing properties for macro; resolved to single value",
                        macro=identity.to_zabbix(),
                        resolve=defn.resolve.value,
                        winning_property=winning_prop,
                        ignored_properties=[
                            c[0] for c in contributions if c[0] != winning_prop
                        ],
                    )
                if defn.template is not None:
                    subs: TemplateMacroValues = {
                        k: str(v) for k, v in host_facts.items()
                    }
                    subs.update(defn.defaults)
                    subs.update(mv.extras)
                    resolved_value = _apply_template(defn.template, subs, identity)
                else:
                    resolved_value = mv.value or ""
                description = mv.description or defn.description
            else:  # REGEX
                # Deduplicate values (validator guarantees no None values for regex)
                values = sorted(
                    {mv.value for _, mv in contributions if mv.value is not None}
                )
                if not values:
                    continue
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
                value_type=defn.value_type,
            )
        return result


# ----- YAML loader -----


def read_property_macro_map(path: Union[str, Path]) -> PropertyMacroMapping:
    """Load and validate a property:macro YAML mapping file."""
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

        # Register macro
        if not macro_def.properties:
            logger.warning(
                "Macro definition has no properties. Will be used for removal only.",
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
                properties={
                    p: MacroValue(
                        value=pv.value,
                        description=pv.description,
                        extras={k: str(v) for k, v in pv.get_extra_values().items()},
                    )
                    for p, pv in macro_def.properties.items()
                },
            )
        )

        # Register macro variants with contexts
        for variant in macro_def.contexts:
            if not variant.properties:
                logger.warning(
                    "Macro context variant has no properties. Will be used for removal only.",
                    macro_name=name,
                    context=variant.context,
                )

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
                    template=variant.template,
                    defaults=dict(variant.defaults),
                    properties={
                        p: MacroValue(
                            value=pv.value,
                            description=pv.description,
                            extras={
                                k: str(v) for k, v in pv.get_extra_values().items()
                            },
                        )
                        for p, pv in variant.properties.items()
                    },
                )
            )

    return mapping
