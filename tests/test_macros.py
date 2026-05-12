from __future__ import annotations

import re
from pathlib import Path

import pytest
from inline_snapshot import snapshot
from pydantic import ValidationError
from pytest import TempPathFactory
from zabbix_auto_config.macros import BUILTIN_PLACEHOLDERS
from zabbix_auto_config.macros import ContextType
from zabbix_auto_config.macros import HostFacts
from zabbix_auto_config.macros import MacroIdentity
from zabbix_auto_config.macros import MacroValueType
from zabbix_auto_config.macros import PropertyMacroMapping
from zabbix_auto_config.macros import ResolvedMacro
from zabbix_auto_config.macros import get_placeholders
from zabbix_auto_config.macros import get_substitutions
from zabbix_auto_config.macros import is_valid_macro_name
from zabbix_auto_config.macros import read_property_macro_map


@pytest.mark.parametrize(
    "macro_name,expected",
    [
        # Valid cases
        ("{$MACRO}", True),
        ("{$MACRO_2}", True),
        ("{$MACRO_UNDERSCORE}", True),
        ("{$MACRO_UNDERSCORE2}", True),
        ("{$NAME_WITH_MANY_UNDERSCORES}", True),
        # Edge cases (are valid, but probably shouldn't be!)
        ("{$_}", True),
        ("{$_____}", True),
        ("{$._._._.}", True),
        ("{$.}", True),
        # Invalid cases
        ("{$MACRO_FOREIGN_CHAR_Æ}", False),
        ("{$ÆØÅ}", False),
        ("{$MACRO-WITH-DASH}", False),
        ("{$NO_ENDING_BRACE", False),
        ("$NO_STARTING_BRACE}", False),
        ("{NO_DOLLAR_SIGN}", False),
        ("{$}", False),
    ],
)
def test_is_valid_macro_name(macro_name: str, expected: bool):
    assert is_valid_macro_name(macro_name) == expected


DEFAULT_FACTS = HostFacts(hostname="testhost.example.com")


# Read example mapping file so we know our examples
# are always up-to-date and are valid.
SAMPLE_PROPERTY_MACRO_MAP = (
    Path(__file__).parent.parent
    / "example"
    / "mapping_files"
    / "property_macro_map.yaml"
).read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def sample_property_macro_map_path(tmp_path_factory: TempPathFactory):
    """Creates a sample property macro map file for testing."""
    tmp_path = tmp_path_factory.mktemp("data")
    p = tmp_path / "property_macro_map.yaml"
    p.write_text(SAMPLE_PROPERTY_MACRO_MAP, encoding="utf-8")
    yield p


@pytest.fixture(scope="session")
def macro_map(sample_property_macro_map_path: Path) -> PropertyMacroMapping:
    return read_property_macro_map(sample_property_macro_map_path)


def test_read_property_macro_map(sample_property_macro_map_path: Path):
    m = read_property_macro_map(sample_property_macro_map_path)

    # Dump internal representation of the property macro map
    assert m.model_dump_json(indent=2) == snapshot("""\
{
  "definitions": [
    {
      "identity": {
        "name": "{$ZAC.PLAIN_MACRO}",
        "context": null,
        "context_type": "static"
      },
      "description": null,
      "value_type": "text",
      "resolve": "first",
      "template": null,
      "defaults": {},
      "properties": {
        "barry": {
          "value": "barry value",
          "description": null,
          "values": {},
          "template": null
        },
        "pizza": {
          "value": "pizza value",
          "description": null,
          "values": {},
          "template": null
        },
        "spam": {
          "value": "a spam value",
          "description": null,
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.LAST_MACRO}",
        "context": null,
        "context_type": "static"
      },
      "description": null,
      "value_type": "text",
      "resolve": "last",
      "template": null,
      "defaults": {},
      "properties": {
        "tier_a": {
          "value": "tier_a value",
          "description": null,
          "values": {},
          "template": null
        },
        "tier_m": {
          "value": "tier_m value",
          "description": null,
          "values": {},
          "template": null
        },
        "tier_z": {
          "value": "tier_z value",
          "description": null,
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.REGEX_MACRO}",
        "context": null,
        "context_type": "static"
      },
      "description": "This one has a description!",
      "value_type": "text",
      "resolve": "regex",
      "template": null,
      "defaults": {},
      "properties": {
        "bazinga": {
          "value": "bazinga",
          "description": null,
          "values": {},
          "template": null
        },
        "spam": {
          "value": "spam value",
          "description": null,
          "values": {},
          "template": null
        },
        "grok": {
          "value": "^grok value$",
          "description": "We can override the description for individual properties as well",
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.BASIC_TEMPLATE_MACRO}",
        "context": null,
        "context_type": "static"
      },
      "description": null,
      "value_type": "text",
      "resolve": "first",
      "template": "https://grafana.example.com/d/node?var-host={{hostname}}",
      "defaults": {},
      "properties": {
        "dashboard_node": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://grafana.example.com/d/node?var-host={{hostname}}"
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.ADVANCED_TEMPLATE_MACRO}",
        "context": null,
        "context_type": "static"
      },
      "description": "Agent scrape URL",
      "value_type": "text",
      "resolve": "first",
      "template": "https://{{hostname}}:{{port}}/{{endpoint}}",
      "defaults": {
        "port": "9100",
        "endpoint": "metrics"
      },
      "properties": {
        "monitored_node": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://{{hostname}}:{{port}}/{{endpoint}}"
        },
        "legacy_exporter": {
          "value": null,
          "description": null,
          "values": {
            "port": "9101",
            "endpoint": "metrics"
          },
          "template": "https://{{hostname}}:{{port}}/{{endpoint}}"
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}",
        "context": null,
        "context_type": "static"
      },
      "description": "Ingestion endpoint",
      "value_type": "text",
      "resolve": "first",
      "template": "https://{{hostname}}:{{port}}/{{endpoint}}",
      "defaults": {
        "port": "9100",
        "endpoint": "ingestion"
      },
      "properties": {
        "logs_ingestor": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://{{hostname}}:{{port}}/{{endpoint}}"
        },
        "legacy_ingestor": {
          "value": null,
          "description": null,
          "values": {
            "port": "9100",
            "endpoint": "ingestion"
          },
          "template": "https://{{hostname}}:{{port}}/legacy/{{endpoint}}"
        },
        "older_legacy_ingestor": {
          "value": null,
          "description": null,
          "values": {
            "port": "9101",
            "different_placeholder": "old-ingestor",
            "endpoint": "ingestion"
          },
          "template": "https://{{hostname}}:{{port}}/legacy/{{different_placeholder}}"
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.API_TOKEN}",
        "context": null,
        "context_type": "static"
      },
      "description": "API token used by monitoring scripts",
      "value_type": "secret",
      "resolve": "first",
      "template": null,
      "defaults": {},
      "properties": {
        "has_api_integration": {
          "value": "s3cr3t-t0k3n",
          "description": null,
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.DB_PASSWORD}",
        "context": null,
        "context_type": "static"
      },
      "description": "DB password fetched from Vault",
      "value_type": "vault",
      "resolve": "first",
      "template": null,
      "defaults": {},
      "properties": {
        "uses_vault_secrets": {
          "value": "secret/zabbix/db:password",
          "description": null,
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.OPTIONAL_CONTEXT}",
        "context": null,
        "context_type": "static"
      },
      "description": "This macro has contexts, but is optional",
      "value_type": "text",
      "resolve": "first",
      "template": null,
      "defaults": {},
      "properties": {
        "spam": {
          "value": "value for non-context spam",
          "description": null,
          "values": {},
          "template": null
        },
        "eggs": {
          "value": "value for non-context eggs",
          "description": null,
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.OPTIONAL_CONTEXT}",
        "context": "/tmp",
        "context_type": "static"
      },
      "description": "Description for /tmp context used here",
      "value_type": "text",
      "resolve": "first",
      "template": null,
      "defaults": {},
      "properties": {
        "spam": {
          "value": "20",
          "description": null,
          "values": {},
          "template": null
        },
        "foo": {
          "value": "30",
          "description": null,
          "values": {},
          "template": null
        },
        "baz": {
          "value": "40",
          "description": null,
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.OPTIONAL_CONTEXT}",
        "context": "^/var/log/.*$",
        "context_type": "regex"
      },
      "description": "This macro has contexts, but is optional",
      "value_type": "text",
      "resolve": "first",
      "template": null,
      "defaults": {},
      "properties": {
        "spam": {
          "value": "30",
          "description": null,
          "values": {},
          "template": null
        },
        "bar": {
          "value": "40",
          "description": null,
          "values": {},
          "template": null
        },
        "gux": {
          "value": "50",
          "description": null,
          "values": {},
          "template": null
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.TEMPLATE_AND_CONTEXT}",
        "context": null,
        "context_type": "static"
      },
      "description": "This macro has a template and contexts",
      "value_type": "text",
      "resolve": "first",
      "template": "https://{{hostname}}:{{port}}/ctx/{{endpoint}}",
      "defaults": {
        "port": "9100",
        "endpoint": "defaultendpoint"
      },
      "properties": {}
    },
    {
      "identity": {
        "name": "{$ZAC.TEMPLATE_AND_CONTEXT}",
        "context": "internal",
        "context_type": "static"
      },
      "description": "Description for internal context used here",
      "value_type": "text",
      "resolve": "first",
      "template": "https://{{hostname}}:{{port}}/ctx/{{endpoint}}",
      "defaults": {
        "port": "9100",
        "endpoint": "defaultendpoint"
      },
      "properties": {
        "qux": {
          "value": null,
          "description": null,
          "values": {
            "port": "20",
            "endpoint": "quxpoint"
          },
          "template": "https://{{hostname}}:{{port}}/ctx/{{endpoint}}"
        },
        "quux": {
          "value": null,
          "description": null,
          "values": {
            "endpoint": "quuxpoint"
          },
          "template": "https://{{hostname}}:{{port}}/ctx/{{endpoint}}"
        },
        "corge": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://{{hostname}}:{{port}}/ctx/{{endpoint}}"
        }
      }
    },
    {
      "identity": {
        "name": "{$ZAC.TEMPLATE_AND_CONTEXT}",
        "context": "^site:.*",
        "context_type": "regex"
      },
      "description": "This macro has a template and contexts",
      "value_type": "text",
      "resolve": "first",
      "template": "https://{{hostname}}:{{port}}/internal/{{ctxpoint}}",
      "defaults": {
        "ctxpoint": "regexpoint",
        "port": "9100",
        "endpoint": "defaultendpoint"
      },
      "properties": {
        "waldo": {
          "value": null,
          "description": null,
          "values": {
            "port": "30",
            "ctxpoint": "waldopoint"
          },
          "template": "https://{{hostname}}:{{port}}/internal/{{ctxpoint}}"
        },
        "plugh": {
          "value": null,
          "description": null,
          "values": {
            "ctxpoint": "plughpoint"
          },
          "template": "https://{{hostname}}:{{port}}/internal/{{ctxpoint}}"
        },
        "xyzzy": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://{{hostname}}:{{port}}/internal/{{ctxpoint}}"
        }
      }
    }
  ]
}\
""")


## Tests for the example macro mapping: fetches by property when many macros are defined
def test_property_macro_map_plain_single(macro_map: PropertyMacroMapping):
    # Single value for plain macro
    assert macro_map.get_macros(["pizza"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.PLAIN_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.PLAIN_MACRO}"), value="pizza value"
            )
        }
    )


def test_property_macro_map_plain_multiple(macro_map: PropertyMacroMapping):
    # Multiple values for resolve=first macro - should not combine, since it's not a regex macro
    assert macro_map.get_macros(["pizza", "barry"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.PLAIN_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.PLAIN_MACRO}"), value="barry value"
            )
        }
    )


def test_property_macro_map_plain_single_resolve_last(
    macro_map: PropertyMacroMapping,
):
    # Single value for resolve=last macro
    assert macro_map.get_macros(["tier_m"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.LAST_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"), value="tier_m value"
            )
        }
    )


def test_property_macro_map_plain_multiple_resolve_last(
    macro_map: PropertyMacroMapping,
):
    # Multiple values for resolve=last macro - should pick the alphabetically last property
    assert macro_map.get_macros(
        ["tier_a", "tier_m", "tier_z"], DEFAULT_FACTS
    ) == snapshot(
        {
            "{$ZAC.LAST_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"), value="tier_z value"
            )
        }
    )


def test_property_macro_map_regex_single(macro_map: PropertyMacroMapping):
    # Single value for macro with regex support
    assert macro_map.get_macros(["bazinga"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"),
                value="bazinga",
                description="This one has a description!",
            )
        }
    )


def test_property_macro_map_regex_multiple(macro_map: PropertyMacroMapping):
    # Multiple values for macro with regex support
    assert macro_map.get_macros(["bazinga", "grok"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"),
                value="(^grok value$|bazinga)",
                description="We can override the description for individual properties as well",
            )
        }
    )


def test_property_macro_map_contexts(macro_map: PropertyMacroMapping):
    # Macros with text context
    assert macro_map.get_macros(["foo"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.OPTIONAL_CONTEXT:/tmp}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.OPTIONAL_CONTEXT}", context="/tmp"),
                value="30",
                description="Description for /tmp context used here",
            )
        }
    )


def test_property_macro_map_contexts_regex(macro_map: PropertyMacroMapping):
    # Macros with regex context
    assert macro_map.get_macros(["bar"], DEFAULT_FACTS) == snapshot(
        {
            '{$ZAC.OPTIONAL_CONTEXT:regex:"^/var/log/.*$"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.OPTIONAL_CONTEXT}",
                    context="^/var/log/.*$",
                    context_type=ContextType.REGEX,
                ),
                value="40",
                description="This macro has contexts, but is optional",
            )
        }
    )


def test_property_macro_map_contexts_multiple(macro_map: PropertyMacroMapping):
    # Macros with two different contexts (text and regex)
    assert macro_map.get_macros(["foo", "bar"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.OPTIONAL_CONTEXT:/tmp}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.OPTIONAL_CONTEXT}", context="/tmp"),
                value="30",
                description="Description for /tmp context used here",
            ),
            '{$ZAC.OPTIONAL_CONTEXT:regex:"^/var/log/.*$"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.OPTIONAL_CONTEXT}",
                    context="^/var/log/.*$",
                    context_type=ContextType.REGEX,
                ),
                value="40",
                description="This macro has contexts, but is optional",
            ),
        }
    )


def test_property_macro_map_contexts_multiple_regex(macro_map: PropertyMacroMapping):
    # Macros with two regex contexts with different values for a resolve=first macro
    # (alphabetically first is chosen -> "bar" chosen over "gux")
    assert macro_map.get_macros(["bar", "gux"], DEFAULT_FACTS) == snapshot(
        {
            '{$ZAC.OPTIONAL_CONTEXT:regex:"^/var/log/.*$"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.OPTIONAL_CONTEXT}",
                    context="^/var/log/.*$",
                    context_type=ContextType.REGEX,
                ),
                value="40",
                description="This macro has contexts, but is optional",
            )
        }
    )


def test_template_macro_simple(macro_map: PropertyMacroMapping):
    # Test simple templated macro with no extra values - just host facts
    assert macro_map.get_macros(["dashboard_node"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.BASIC_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.BASIC_TEMPLATE_MACRO}"),
                value="https://grafana.example.com/d/node?var-host=testhost.example.com",
            )
        }
    )


def test_template_macro_extra_placeholders_default(macro_map: PropertyMacroMapping):
    # Test templated macro with extra placeholders
    assert macro_map.get_macros(["monitored_node"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.ADVANCED_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.ADVANCED_TEMPLATE_MACRO}"),
                value="https://testhost.example.com:9100/metrics",
                description="Agent scrape URL",
            )
        }
    )


def test_template_macro_extra_placeholders_override(macro_map: PropertyMacroMapping):
    # Test templated macro with extra placeholders
    assert macro_map.get_macros(["legacy_exporter"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.ADVANCED_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.ADVANCED_TEMPLATE_MACRO}"),
                value="https://testhost.example.com:9101/metrics",
                description="Agent scrape URL",
            )
        }
    )


def test_template_macro_extra_placeholders_multiple(macro_map: PropertyMacroMapping):
    # Test templated macro with extra placeholders (resolve to `legacy_exporter` because of alphabetical order)
    assert macro_map.get_macros(
        ["monitored_node", "legacy_exporter"], DEFAULT_FACTS
    ) == snapshot(
        {
            "{$ZAC.ADVANCED_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.ADVANCED_TEMPLATE_MACRO}"),
                value="https://testhost.example.com:9101/metrics",
                description="Agent scrape URL",
            )
        }
    )


def test_template_macro_property_template_override(macro_map: PropertyMacroMapping):
    """Test templated macro with property that defines new template (with the same placeholders)."""
    assert macro_map.get_macros(["legacy_ingestor"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}"
                ),
                value="https://testhost.example.com:9100/legacy/ingestion",
                description="Ingestion endpoint",
            )
        }
    )


def test_template_macro_per_property_template_overrides(
    macro_map: PropertyMacroMapping,
):
    """Test templated macro with properties that override the template and values on a per-property basis."""
    assert macro_map.get_macros(["older_legacy_ingestor"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}"
                ),
                value="https://testhost.example.com:9101/legacy/old-ingestor",
                description="Ingestion endpoint",
            )
        }
    )


def test_template_macro_with_context_text(macro_map: PropertyMacroMapping):
    """Test template macro with text context."""

    # Inherits no defaults - specifies all values itself
    assert macro_map.get_macros(["qux"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.TEMPLATE_AND_CONTEXT:internal}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}", context="internal"
                ),
                value="https://testhost.example.com:20/ctx/quxpoint",
                description="Description for internal context used here",
            )
        }
    )
    # Inherits partial defaults - missing port
    assert macro_map.get_macros(["quux"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.TEMPLATE_AND_CONTEXT:internal}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}", context="internal"
                ),
                value="https://testhost.example.com:9100/ctx/quuxpoint",
                description="Description for internal context used here",
            )
        }
    )

    # Inherits all defaults
    assert macro_map.get_macros(["corge"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.TEMPLATE_AND_CONTEXT:internal}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}", context="internal"
                ),
                value="https://testhost.example.com:9100/ctx/defaultendpoint",
                description="Description for internal context used here",
            )
        }
    )


def test_template_macro_with_context_regex(macro_map: PropertyMacroMapping):
    """Test template macro with regex context."""

    # Inherits no defaults - specifies all values itself
    assert macro_map.get_macros(["waldo"], DEFAULT_FACTS) == snapshot(
        {
            '{$ZAC.TEMPLATE_AND_CONTEXT:regex:"^site:.*"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}",
                    context="^site:.*",
                    context_type=ContextType.REGEX,
                ),
                value="https://testhost.example.com:30/internal/waldopoint",
                description="This macro has a template and contexts",
            )
        }
    )
    # Inherits partial defaults - missing port
    assert macro_map.get_macros(["plugh"], DEFAULT_FACTS) == snapshot(
        {
            '{$ZAC.TEMPLATE_AND_CONTEXT:regex:"^site:.*"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}",
                    context="^site:.*",
                    context_type=ContextType.REGEX,
                ),
                value="https://testhost.example.com:9100/internal/plughpoint",
                description="This macro has a template and contexts",
            )
        }
    )

    # Inherits all defaults
    assert macro_map.get_macros(["xyzzy"], DEFAULT_FACTS) == snapshot(
        {
            '{$ZAC.TEMPLATE_AND_CONTEXT:regex:"^site:.*"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}",
                    context="^site:.*",
                    context_type=ContextType.REGEX,
                ),
                value="https://testhost.example.com:9100/internal/regexpoint",
                description="This macro has a template and contexts",
            )
        }
    )


def test_property_macro_map_secret(macro_map: PropertyMacroMapping):
    # Single value for secret macro
    assert macro_map.get_macros(["has_api_integration"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.API_TOKEN}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.API_TOKEN}"),
                value="s3cr3t-t0k3n",
                description="API token used by monitoring scripts",
                value_type=MacroValueType.SECRET,
            )
        }
    )


def test_property_macro_map_vault(macro_map: PropertyMacroMapping):
    # Single value for vault macro
    assert macro_map.get_macros(["uses_vault_secrets"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.DB_PASSWORD}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.DB_PASSWORD}"),
                value="secret/zabbix/db:password",
                description="DB password fetched from Vault",
                value_type=MacroValueType.VAULT,
            )
        }
    )


def get_all_properties_from_mapping(macro_map: PropertyMacroMapping) -> list[str]:
    """Helper function to get all properties defined in the macro map."""
    return list(macro_map._by_property.keys())


def test_property_map_properties(macro_map: PropertyMacroMapping) -> None:
    """Snapshot test for verifying changes to defined properties in example mapping."""
    assert get_all_properties_from_mapping(macro_map) == snapshot(
        [
            "barry",
            "pizza",
            "spam",
            "tier_a",
            "tier_m",
            "tier_z",
            "bazinga",
            "grok",
            "dashboard_node",
            "monitored_node",
            "legacy_exporter",
            "logs_ingestor",
            "legacy_ingestor",
            "older_legacy_ingestor",
            "has_api_integration",
            "uses_vault_secrets",
            "eggs",
            "foo",
            "baz",
            "bar",
            "gux",
            "qux",
            "quux",
            "corge",
            "waldo",
            "plugh",
            "xyzzy",
        ]
    )


def test_property_macro_map_combined(macro_map: PropertyMacroMapping):
    """Test resolving macros for _all_ defined properties."""
    assert macro_map.get_macros(
        get_all_properties_from_mapping(macro_map),
        DEFAULT_FACTS,
    ) == snapshot(
        {
            "{$ZAC.PLAIN_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.PLAIN_MACRO}"), value="barry value"
            ),
            "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"),
                value="(^grok value$|bazinga|spam value)",
                description="We can override the description for individual properties as well",
            ),
            "{$ZAC.OPTIONAL_CONTEXT}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.OPTIONAL_CONTEXT}"),
                value="value for non-context eggs",
                description="This macro has contexts, but is optional",
            ),
            "{$ZAC.OPTIONAL_CONTEXT:/tmp}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.OPTIONAL_CONTEXT}", context="/tmp"),
                value="40",
                description="Description for /tmp context used here",
            ),
            '{$ZAC.OPTIONAL_CONTEXT:regex:"^/var/log/.*$"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.OPTIONAL_CONTEXT}",
                    context="^/var/log/.*$",
                    context_type=ContextType.REGEX,
                ),
                value="40",
                description="This macro has contexts, but is optional",
            ),
            "{$ZAC.LAST_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"), value="tier_z value"
            ),
            "{$ZAC.BASIC_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.BASIC_TEMPLATE_MACRO}"),
                value="https://grafana.example.com/d/node?var-host=testhost.example.com",
            ),
            "{$ZAC.ADVANCED_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.ADVANCED_TEMPLATE_MACRO}"),
                value="https://testhost.example.com:9101/metrics",
                description="Agent scrape URL",
            ),
            "{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}"
                ),
                value="https://testhost.example.com:9100/legacy/ingestion",
                description="Ingestion endpoint",
            ),
            "{$ZAC.TEMPLATE_AND_CONTEXT:internal}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}", context="internal"
                ),
                value="https://testhost.example.com:9100/ctx/defaultendpoint",
                description="Description for internal context used here",
            ),
            '{$ZAC.TEMPLATE_AND_CONTEXT:regex:"^site:.*"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}",
                    context="^site:.*",
                    context_type=ContextType.REGEX,
                ),
                value="https://testhost.example.com:9100/internal/plughpoint",
                description="This macro has a template and contexts",
            ),
            "{$ZAC.API_TOKEN}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.API_TOKEN}"),
                value="s3cr3t-t0k3n",
                description="API token used by monitoring scripts",
                value_type=MacroValueType.SECRET,
            ),
            "{$ZAC.DB_PASSWORD}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.DB_PASSWORD}"),
                value="secret/zabbix/db:password",
                description="DB password fetched from Vault",
                value_type=MacroValueType.VAULT,
            ),
        }
    )


def contains_valid_regex(macros: dict[str, ResolvedMacro]) -> bool:
    """Ensure mapping contains valid regex patterns for all macros (if any)."""
    import re

    for name, macro in macros.items():
        try:
            re.compile(macro.value)
        except re.error:
            pytest.fail(f"Invalid regex pattern for macro {name}: {macro.value}")
    return True


def test_get_macros_deduplication_regex_plain(tmp_path: Path):
    """Test deduplication of plain text values for regex macros."""
    tmpfile = tmp_path / "property_macro_map.txt"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      default_db: postgresql
      is_pgsql_server: postgresql
      zabbix_agent: zabbix-agent
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Resolve to single value
    macros = m.get_macros(["default_db", "is_pgsql_server"], DEFAULT_FACTS)
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="postgresql",
            )
        }
    )
    assert contains_valid_regex(macros)

    # Resolve to simple OR regex pattern
    macros = m.get_macros(
        ["default_db", "is_pgsql_server", "zabbix_agent"], DEFAULT_FACTS
    )
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="(postgresql|zabbix-agent)",
            )
        }
    )
    assert contains_valid_regex(macros)


def test_get_macros_deduplication_regex_pattern(tmp_path: Path):
    tmpfile = tmp_path / "property_macro_map.txt"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      default_db: ^postgresql(\d+)?$
      is_pgsql_server: ^postgresql(\d+)?$
      zabbix_agent: ^zabbix-agent(\d+)?$
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Test that duplicate values are deduplicated for regex macros
    macros = m.get_macros(
        ["default_db", "is_pgsql_server", "zabbix_agent"], DEFAULT_FACTS
    )
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="(^postgresql(\\d+)?$|^zabbix-agent(\\d+)?$)",
            )
        }
    )
    assert contains_valid_regex(macros)


def test_get_macros_deduplication_regex_mixed(tmp_path: Path):
    """Test deduplication of mixed plain text and regex values for regex macros."""
    tmpfile = tmp_path / "property_macro_map.txt"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      default_db: postgresql
      is_pgsql_server: postgresql
      zabbix_agent: ^zabbix-agent(\d+)?$

""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Test that duplicate values are deduplicated for regex macros
    macros = m.get_macros(["default_db", "is_pgsql_server"], DEFAULT_FACTS)
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="postgresql",
            )
        }
    )
    assert contains_valid_regex(macros)


def test_get_macros_regex_patterns(tmp_path: Path):
    """Test that the generated regex patterns are valid and correctly combined."""
    tmpfile = tmp_path / "property_macro_map.txt"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      is_pgsql_server: ^postgresql(\d+)?$
      zabbix_agent: ^zabbix-agent(\d+)?$
      use_zabbix_agent2: ^zabbix-agent2$
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Combinations of regex patterns
    macros = m.get_macros(["is_pgsql_server", "zabbix_agent"], DEFAULT_FACTS)
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="(^postgresql(\\d+)?$|^zabbix-agent(\\d+)?$)",
            )
        }
    )
    assert contains_valid_regex(macros)

    macros = m.get_macros(["zabbix_agent", "use_zabbix_agent2"], DEFAULT_FACTS)
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="(^zabbix-agent(\\d+)?$|^zabbix-agent2$)",
            )
        }
    )
    assert contains_valid_regex(macros)

    # Individual regex patterns
    macros = m.get_macros(["zabbix_agent"], DEFAULT_FACTS)
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="^zabbix-agent(\\d+)?$",
            )
        }
    )
    assert contains_valid_regex(macros)

    macros = m.get_macros(["use_zabbix_agent2"], DEFAULT_FACTS)
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="^zabbix-agent2$",
            )
        }
    )
    assert contains_valid_regex(macros)

    macros = m.get_macros(["is_pgsql_server"], DEFAULT_FACTS)
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="^postgresql(\\d+)?$",
            )
        }
    )
    assert contains_valid_regex(macros)


def test_get_macros_template_no_defaults(tmp_path: Path):
    """Test that template macros without a `defaults` section fails"""
    tmpfile = tmp_path / "property_macro_map.txt"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        r"""
macros:
  "{$AGENT.URL}":
    description: "Agent scrape URL"
    template: "https://{{hostname}}:{{port}}/metrics"
    properties:
      monitored_node:
      legacy_exporter:
        values:
          port: 9101              # overrides default
""",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=re.escape(
            "Template placeholders not satisfied: {'monitored_node': ['port']}"
        ),
    ):
        _ = read_property_macro_map(tmpfile)


def test_get_macros_template_incomplete_defaults(tmp_path: Path):
    """Test that template macros without a complete `defaults` section fails."""
    tmpfile = tmp_path / "property_macro_map.txt"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        r"""
macros:
    "{$AGENT.URL}":
      description: "Agent scrape URL"
      template: "https://{{hostname}}:{{port}}/{{endpoint}}"
      defaults:
        port: 9100
        # missing `endpoint`
      properties:
        monitored_node:           # uses default port 9100
        legacy_exporter:
          values:
            port: 9101              # overrides default
""",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=re.escape(
            "Template placeholders not satisfied: {'monitored_node': ['endpoint'], 'legacy_exporter': ['endpoint']}"
        ),
    ):
        _ = read_property_macro_map(tmpfile)


def test_resolve_last(tmp_path: Path):
    """`resolve: last` picks alphabetically last contributing property."""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.LAST_MACRO}":
    resolve: last
    properties:
      apple: "apple value"
      banana: "banana value"
      cherry: "cherry value"
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Single property -> that property's value
    assert m.get_macros(["apple"], DEFAULT_FACTS) == {
        "{$ZAC.LAST_MACRO}": ResolvedMacro(
            identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"), value="apple value"
        )
    }

    # Multiple properties -> alphabetically last value wins
    assert m.get_macros(["apple", "banana", "cherry"], DEFAULT_FACTS) == {
        "{$ZAC.LAST_MACRO}": ResolvedMacro(
            identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"), value="cherry value"
        )
    }


def test_template_macro_rejects_resolve_regex(tmp_path: Path):
    """Template macros must not use `resolve: regex`."""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.TEMPLATE_MACRO}":
    resolve: regex
    template: "https://{{hostname}}/x"
    properties:
      foo:
""",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=re.escape("template macros do not support resolve=regex"),
    ):
        _ = read_property_macro_map(tmpfile)


def test_context_macro_with_template(tmp_path: Path):
    """Context macros must not use `resolve: regex`."""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.CONTEXT_MACRO}":
    resolve: first
    template: "https://{{hostname}}/ctx/{{ctx}}"
    defaults:
      ctx: bar
    contexts:
      - context: "plaintext"
        description: "Context description"
        properties:
          foo:
            values:
                ctx: "foo value 123"
      - context: "^somepattern.*$"
        context_type: regex
        description: "Regex context description"
        properties:
          foo:
            values:
                ctx: "foo value 456"
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)
    assert m.get_macros(["foo"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.CONTEXT_MACRO:plaintext}": ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.CONTEXT_MACRO}", context="plaintext"
                ),
                value="https://testhost.example.com/ctx/foo value 123",
                description="Context description",
            ),
            '{$ZAC.CONTEXT_MACRO:regex:"^somepattern.*$"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.CONTEXT_MACRO}",
                    context="^somepattern.*$",
                    context_type=ContextType.REGEX,
                ),
                value="https://testhost.example.com/ctx/foo value 456",
                description="Regex context description",
            ),
        }
    )


def test_context_macro_with_overriden_template(tmp_path: Path):
    """Context macro with template and contexts that override template + placeholders."""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.TEMPLATE_AND_CONTEXT}":
    template: "https://{{hostname}}:{{port}}/ctx/{{ctx}}"
    defaults:
      port: 9100
      ctx: defaultctx
    properties:
      spam:
    contexts:
      - context: "^site:.*"
        context_type: regex
        template: "https://{{hostname}}:{{port}}/internal/{{blah}}" # can override top-level template
        defaults:
            # inherits port
            blah: "blahval"
        properties:
          spam:
            values:
                port: 30
                blah: "spamington"
          bar:
            values:
              blah: "barval"
          gux:

""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)
    assert m.get_macros(["spam"], DEFAULT_FACTS) == snapshot(
        {
            "{$ZAC.TEMPLATE_AND_CONTEXT}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.TEMPLATE_AND_CONTEXT}"),
                value="https://testhost.example.com:9100/ctx/defaultctx",
            ),
            '{$ZAC.TEMPLATE_AND_CONTEXT:regex:"^site:.*"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.TEMPLATE_AND_CONTEXT}",
                    context="^site:.*",
                    context_type=ContextType.REGEX,
                ),
                value="https://testhost.example.com:30/internal/spamington",
            ),
        }
    )


def test_context_macro_with_template_invalid(tmp_path: Path):
    """Context macros with templates must not use `resolve: regex`."""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.CONTEXT_MACRO}":
    resolve: regex
    contexts:
      - context: "plaintext"
        description: "Context description"
        template: "https://{{hostname}}/ctx/{{ctx}}"
        properties:
          foo:
            values:
              ctx: "foo value 123"
      - context: "^somepattern.*$"
        description: "Regex context description"
        template: "https://{{hostname}}/ctx/{{ctx}}"
        properties:
          foo:
            values:
              ctx: "foo value 456"
""",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=re.escape("uses template; parent must not use resolve=regex"),
    ):
        _ = read_property_macro_map(tmpfile)


def test_template_macro_property_unused_values(tmp_path: Path) -> None:
    """Test passing in incorrect placeholder to a property of a template macro.

    NOTE
    ----
    Currently we don't flag this as an error, since the property simply
    inherits the missing value from the defaults when resolved.
    The incorrect placeholder is simply ignored.
    """
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.TEMPLATE_UNUSED_VALUE}":
    description: "Ingestion endpoint"
    template: "https://{{hostname}}:{{port}}/{{endpoint}}"
    defaults:
      port: 9100
      endpoint: ingestion
    properties:
      foo:
        values:
          port: 910
          wrong_placeholder: old-ingestor # will not be used
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)
    macros = m.get_macros(["foo"], DEFAULT_FACTS)
    assert len(macros) == 1
    assert (
        # Macro inherits the missing `endpoint` value from defaults
        # while `wrong_placeholder` is ignored.
        macros["{$ZAC.TEMPLATE_UNUSED_VALUE}"].value
        == "https://testhost.example.com:910/ingestion"
    )


def test_template_no_defaults_no_properties(tmp_path: Path) -> None:
    """Template macro with no properties doesn't need defaults (no properties to validate)"""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.TEMPLATE_NO_PROPS}":
    template: "https://{{hostname}}:{{port}}/{{endpoint}}"
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)  # reads fine
    assert len(m.definitions) == 1


def test_template_no_defaults_with_properties(tmp_path: Path) -> None:
    """Template macro with properties must have defaults to satisfy placeholders."""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.TEMPLATE_PROPS_NO_DEFAULTS}":
    template: "https://{{hostname}}:{{port}}/{{endpoint}}"
    properties:
      foo:
""",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=re.escape(
            "Template placeholders not satisfied: {'foo': ['endpoint', 'port']}"
        ),
    ):
        _ = read_property_macro_map(tmpfile)


def test_get_substitutions(tmp_path: Path) -> None:
    """Test `get_substitutions using a macro with template+template override in properties."""
    tmpfile = tmp_path / "property_macro_map.yaml"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        """
macros:
  "{$ZAC.ADVANCED_TEMPLATE_MACRO_PROPERTY_OVERRIDE}":
    description: "Ingestion endpoint"
    template: "https://{{hostname}}:{{port}}/{{endpoint}}"
    defaults:
      port: 9100
      endpoint: ingestion
    properties:
      logs_ingestor:
      # Overrides template only (same placeholders)
      legacy_ingestor:
        template: "https://{{hostname}}:{{port}}/legacy/{{endpoint}}"
      older_legacy_ingestor:
        template: "https://{{hostname}}:{{port}}/legacy/{{different_placeholder}}"
        values:
          port: 910
          different_placeholder: old-ingestor
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)
    assert len(m.definitions) == 1
    defn = m.definitions[0]

    # No overrides in property
    prop_1 = defn.properties["logs_ingestor"]
    subs_1 = get_substitutions(defn, prop_1, DEFAULT_FACTS, "logs_ingestor")
    assert subs_1 == snapshot(
        {
            "hostname": "testhost.example.com",
            "port": "9100",
            "endpoint": "ingestion",
            "property": "logs_ingestor",
        }
    )

    # Overrides template with identical placeholders -> identical sub keys
    prop_2 = defn.properties["legacy_ingestor"]
    subs_2 = get_substitutions(defn, prop_2, DEFAULT_FACTS, "legacy_ingestor")
    assert subs_2.keys() == subs_1.keys()
    assert subs_2 == snapshot(
        {
            "hostname": "testhost.example.com",
            "port": "9100",
            "endpoint": "ingestion",
            "property": "legacy_ingestor",
        }
    )

    # Overrides template with new placeholders -> new sub keys
    prop_3 = defn.properties["older_legacy_ingestor"]
    subs_3 = get_substitutions(defn, prop_3, DEFAULT_FACTS, "older_legacy_ingestor")
    assert subs_3.keys() != subs_1.keys()
    assert subs_3 == snapshot(
        {
            "hostname": "testhost.example.com",
            "port": "910",
            "endpoint": "ingestion",
            "different_placeholder": "old-ingestor",
            "property": "older_legacy_ingestor",
        }
    )


def test_builtin_placeholder_keys() -> None:
    """Snapshot test to catch changes to builtin placeholder keys (host facts, resolved macro properties, etc.)"""
    assert BUILTIN_PLACEHOLDERS == snapshot(frozenset({"hostname", "property"}))


def test_get_substitutions_builtin_placeholder_keys_are_used(
    macro_map: PropertyMacroMapping,
) -> None:
    """Test that template placeholder substitutions are resolved correctly and contain the expected keys."""

    all_macros = list(macro_map._by_property.items())  # pyright: ignore[reportPrivateUsage]
    assert len(all_macros) > 0, (
        "No macros found in the mapping to test substitutions for"
    )

    for prop_name, macros in all_macros:
        for macro in macros:
            if not macro.properties:  # no properties to test for
                continue
            for prop in macro.properties.values():
                if not prop.template:
                    continue

                subs = get_substitutions(macro, prop, DEFAULT_FACTS, prop_name)
                placeholders = get_placeholders(prop.template)

                # All placeholders satisfied
                assert placeholders.issubset(subs.keys())

                # Resolved substitutions contain 'builtins', defaults, values
                expect = BUILTIN_PLACEHOLDERS | set(macro.defaults) | set(prop.values)
                assert expect.issubset(subs.keys())
