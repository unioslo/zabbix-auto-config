from __future__ import annotations

import re
from pathlib import Path

import pytest
from inline_snapshot import snapshot
from pydantic import ValidationError
from pytest import TempPathFactory
from zabbix_auto_config.macros import ContextType
from zabbix_auto_config.macros import HostFacts
from zabbix_auto_config.macros import MacroIdentity
from zabbix_auto_config.macros import MacroValueType
from zabbix_auto_config.macros import PropertyMacroMapping
from zabbix_auto_config.macros import ResolvedMacro
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
          "extras": {}
        },
        "pizza": {
          "value": "pizza value",
          "description": null,
          "extras": {}
        },
        "spam": {
          "value": "a spam value",
          "description": null,
          "extras": {}
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
          "extras": {}
        },
        "tier_m": {
          "value": "tier_m value",
          "description": null,
          "extras": {}
        },
        "tier_z": {
          "value": "tier_z value",
          "description": null,
          "extras": {}
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
          "extras": {}
        },
        "spam": {
          "value": "spam value",
          "description": null,
          "extras": {}
        },
        "grok": {
          "value": "^grok value$",
          "description": "We can override the description for individual properties as well",
          "extras": {}
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
          "extras": {}
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
          "extras": {}
        },
        "legacy_exporter": {
          "value": null,
          "description": null,
          "extras": {
            "port": "9101"
          }
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
          "extras": {}
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
          "extras": {}
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
          "extras": {}
        },
        "eggs": {
          "value": "value for non-context eggs",
          "description": null,
          "extras": {}
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
          "extras": {}
        },
        "foo": {
          "value": "30",
          "description": null,
          "extras": {}
        },
        "baz": {
          "value": "40",
          "description": null,
          "extras": {}
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
          "extras": {}
        },
        "bar": {
          "value": "40",
          "description": null,
          "extras": {}
        },
        "gux": {
          "value": "50",
          "description": null,
          "extras": {}
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
          "extras": {
            "port": "20",
            "endpoint": "quxpoint"
          }
        },
        "quux": {
          "value": null,
          "description": null,
          "extras": {
            "endpoint": "quuxpoint"
          }
        },
        "corge": {
          "value": null,
          "description": null,
          "extras": {}
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
          "extras": {
            "port": "30",
            "ctxpoint": "waldopoint"
          }
        },
        "plugh": {
          "value": null,
          "description": null,
          "extras": {
            "ctxpoint": "plughpoint"
          }
        },
        "xyzzy": {
          "value": null,
          "description": null,
          "extras": {}
        }
      }
    }
  ]
}\
""")


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


def test_property_macro_map_combined(macro_map: PropertyMacroMapping):
    # Macro with multiple properties, some of which are shared between macros
    # Combine everything
    assert macro_map.get_macros(
        [
            # Plain
            "pizza",
            "barry",
            "spam",
            "eggs",
            "ham",
            "grok",
            "bazinga",
            # Context
            "foo",
            "bar",
            "baz",
            "gux",
            # Template
            "dashboard_node",
            "monitored_node",
            "legacy_exporter",
            # Secret
            "has_api_integration",
            # Vault
            "uses_vault_secrets",
        ],
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
            "{$ZAC.BASIC_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.BASIC_TEMPLATE_MACRO}"),
                value="https://grafana.example.com/d/node?var-host=testhost.example.com",
            ),
            "{$ZAC.ADVANCED_TEMPLATE_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.ADVANCED_TEMPLATE_MACRO}"),
                value="https://testhost.example.com:9101/metrics",
                description="Agent scrape URL",
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
      monitored_node:           # uses default port 9100
      legacy_exporter:
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
            ctx: "foo value 123"
      - context: "^somepattern.*$"
        context_type: regex
        description: "Regex context description"
        properties:
          foo:
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
            port: 30
            blah: "bazinga"
          bar:
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
                value="https://testhost.example.com:30/internal/bazinga",
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
        template: "https://{{hostname}}/ctx/{{ctx}}" # templates not allowed for context macros
        properties:
          foo:
            ctx: "foo value 123"
      - context: "^somepattern.*$"
        description: "Regex context description"
        template: "https://{{hostname}}/ctx/{{ctx}}" # templates not allowed for context macros
        properties:
          foo:
            ctx: "foo value 456"
""",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=re.escape("uses template; parent must not use resolve=regex"),
    ):
        _ = read_property_macro_map(tmpfile)
