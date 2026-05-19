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
from zabbix_auto_config.macros import MacroDefIn
from zabbix_auto_config.macros import MacroIdentity
from zabbix_auto_config.macros import MacroValueType
from zabbix_auto_config.macros import PropertyMacroMapping
from zabbix_auto_config.macros import ResolvedMacro
from zabbix_auto_config.macros import get_host_facts
from zabbix_auto_config.macros import get_placeholders
from zabbix_auto_config.macros import get_substitutions
from zabbix_auto_config.macros import is_valid_macro_name
from zabbix_auto_config.macros import read_property_macro_map
from zabbix_auto_config.models import Host
from zabbix_auto_config.models import Interface

DEFAULT_FACTS = HostFacts(hostname="testhost.example.com")


# Read example mapping file so we know our examples
# are always up-to-date and are valid.
SAMPLE_PROPERTY_MACRO_MAP = (
    Path(__file__).parent.parent
    / "example"
    / "mapping_files"
    / "property_macro_map.yaml"
).read_text(encoding="utf-8")


def _write_yaml(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "property_macro_map.yaml"
    p.write_text(body, encoding="utf-8")  # pyright: ignore[reportUnusedCallResult]
    return p


def _load_mapping(tmp_path: Path, body: str) -> PropertyMacroMapping:
    """Helper function to write a mapping file and load it."""
    p = _write_yaml(tmp_path, body)
    return read_property_macro_map(p)


@pytest.fixture(scope="session")
def sample_property_macro_map_path(tmp_path_factory: TempPathFactory):
    """Creates a sample property macro map file for testing."""
    tmp_path = tmp_path_factory.mktemp("data")
    p = _write_yaml(tmp_path, SAMPLE_PROPERTY_MACRO_MAP)
    yield p


@pytest.fixture(scope="session")
def macro_map(sample_property_macro_map_path: Path) -> PropertyMacroMapping:
    return read_property_macro_map(sample_property_macro_map_path)


def contains_valid_regex(macros: dict[str, ResolvedMacro]) -> bool:
    """Ensure mapping contains valid regex patterns for all macros (if any)."""
    for name, macro in macros.items():
        try:
            re.compile(macro.value)
        except re.error:
            pytest.fail(f"Invalid regex pattern for macro {name}: {macro.value}")
    return True


def get_all_properties_from_mapping(macro_map: PropertyMacroMapping) -> list[str]:
    """Helper function to get all properties defined in the macro map."""
    return list(macro_map._by_property.keys())


class TestMacroNameValidation:
    """Tests for macro name validation."""

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
    def test_valid_and_invalid_names(self, macro_name: str, expected: bool):
        assert is_valid_macro_name(macro_name) == expected

    @pytest.mark.parametrize(
        "name",
        [
            "{$ZAC.INVALID",
            "ZAC.INVALID}",
            "{$ZAC.INV{ALID}",
            "{$ZAC.INVALID}EXTRA",
            "{$ZAC.INV@LID}",
            "ZAC.INVALID",
        ],
    )
    def test_invalid_macro_name_in_yaml(
        self,
        tmp_path: Path,
        name: str,
    ) -> None:
        """Macro name without closing curly brace."""
        with pytest.raises(
            ValidationError,
            match=re.escape(f"Invalid macro name: '{name}'"),
        ):
            _ = _load_mapping(
                tmp_path,
                f"""
macros:
  "{name}":
""",
            )


class TestMappingFileLoad:
    """Tests for loading and validating the property macro mapping file."""

    def test_read_example_mapping_snapshot(self, sample_property_macro_map_path: Path):
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
      "description": "Macro description",
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
          "description": "Custom spam description",
          "values": {},
          "template": null
        }
      },
      "hosts": {}
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
      },
      "hosts": {}
    },
    {
      "identity": {
        "name": "{$ZAC.REGEX_MACRO}",
        "context": null,
        "context_type": "static"
      },
      "description": null,
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
          "description": null,
          "values": {},
          "template": null
        }
      },
      "hosts": {}
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
      },
      "hosts": {}
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
      },
      "hosts": {}
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
      },
      "hosts": {}
    },
    {
      "identity": {
        "name": "{$ZAC.SIMPLE_PARENT_ADVANCED_CHILD}",
        "context": null,
        "context_type": "static"
      },
      "description": "Ingestion endpoint",
      "value_type": "text",
      "resolve": "first",
      "template": "{{value}}",
      "defaults": {
        "value": "defaultval"
      },
      "properties": {
        "default_ingestor": {
          "value": null,
          "description": null,
          "values": {
            "value": "foo_val"
          },
          "template": "{{value}}"
        },
        "labeled_ingestor": {
          "value": null,
          "description": null,
          "values": {
            "value": "defaultval"
          },
          "template": "value: {{value}}"
        },
        "json_ingestor": {
          "value": null,
          "description": null,
          "values": {
            "port": "9101",
            "endpoint": "healthcheck",
            "value": "defaultval"
          },
          "template": "{\\"endpoint\\": \\"{{endpoint}}\\", \\"port\\": \\"{{port}}\\"}"
        }
      },
      "hosts": {}
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
      },
      "hosts": {}
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
      },
      "hosts": {}
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
      },
      "hosts": {}
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
      },
      "hosts": {}
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
      },
      "hosts": {}
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
      "properties": {},
      "hosts": {}
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
            "endpoint": "quuxpoint",
            "port": "9100"
          },
          "template": "https://{{hostname}}:{{port}}/ctx/{{endpoint}}"
        },
        "corge": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://{{hostname}}:{{port}}/ctx/{{endpoint}}"
        }
      },
      "hosts": {}
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
            "ctxpoint": "waldopoint",
            "endpoint": "defaultendpoint"
          },
          "template": "https://{{hostname}}:{{port}}/internal/{{ctxpoint}}"
        },
        "plugh": {
          "value": null,
          "description": null,
          "values": {
            "ctxpoint": "plughpoint",
            "port": "9100",
            "endpoint": "defaultendpoint"
          },
          "template": "https://{{hostname}}:{{port}}/internal/{{ctxpoint}}"
        },
        "xyzzy": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://{{hostname}}:{{port}}/internal/{{ctxpoint}}"
        }
      },
      "hosts": {}
    },
    {
      "identity": {
        "name": "{$ZAC.HOST_OVERRIDDEN}",
        "context": null,
        "context_type": "static"
      },
      "description": "Per-host scrape URL",
      "value_type": "text",
      "resolve": "first",
      "template": "https://{{hostname}}:{{port}}/{{endpoint}}",
      "defaults": {
        "port": "9100",
        "endpoint": "metrics"
      },
      "properties": {
        "host_overridden_node": {
          "value": null,
          "description": null,
          "values": {},
          "template": "https://{{hostname}}:{{port}}/{{endpoint}}"
        }
      },
      "hosts": {
        "special.example.com": {
          "value": null,
          "description": null,
          "values": {
            "port": "9500",
            "endpoint": "special-metrics"
          },
          "template": "https://{{hostname}}:{{port}}/{{endpoint}}"
        },
        ".*\\\\.legacy\\\\.example\\\\.com": {
          "value": null,
          "description": null,
          "values": {
            "port": "9101",
            "endpoint": "metrics"
          },
          "template": "https://{{hostname}}:{{port}}/{{endpoint}}"
        }
      }
    }
  ]
}\
""")

    def test_example_properties_snapshot(self, macro_map: PropertyMacroMapping) -> None:
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
                "default_ingestor",
                "labeled_ingestor",
                "json_ingestor",
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
                "host_overridden_node",
            ]
        )

    def test_resolve_all_example_properties(self, macro_map: PropertyMacroMapping):
        """Test resolving macros for _all_ defined properties."""
        assert macro_map.get_macros(
            get_all_properties_from_mapping(macro_map),
            DEFAULT_FACTS,
        ) == snapshot(
            {
                "{$ZAC.PLAIN_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.PLAIN_MACRO}"),
                    value="barry value",
                    description="Macro description",
                ),
                "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"),
                    value="(^grok value$|bazinga|spam value)",
                ),
                "{$ZAC.OPTIONAL_CONTEXT}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.OPTIONAL_CONTEXT}"),
                    value="value for non-context eggs",
                    description="This macro has contexts, but is optional",
                ),
                "{$ZAC.OPTIONAL_CONTEXT:/tmp}": ResolvedMacro(
                    identity=MacroIdentity(
                        name="{$ZAC.OPTIONAL_CONTEXT}", context="/tmp"
                    ),
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
                    identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"),
                    value="tier_z value",
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
                "{$ZAC.SIMPLE_PARENT_ADVANCED_CHILD}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.SIMPLE_PARENT_ADVANCED_CHILD}"),
                    value="foo_val",
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
                "{$ZAC.HOST_OVERRIDDEN}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.HOST_OVERRIDDEN}"),
                    value="https://testhost.example.com:9100/metrics",
                    description="Per-host scrape URL",
                ),
            }
        )

    def test_empty_definitions_supported(
        self,
        tmp_path: Path,
    ) -> None:
        """Ensure empty macro definitions (used for removal) are supported."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.I_AM_EMPTY}":
  "{$ZAC.I_AM_ALSO_EMPTY}":
""",
        )
        assert len(m.definitions) == 2
        assert len(m._by_property) == 0  # pyright: ignore[reportPrivateUsage]
        assert sorted(m.identity.to_zabbix() for m in m.definitions) == snapshot(
            ["{$ZAC.I_AM_ALSO_EMPTY}", "{$ZAC.I_AM_EMPTY}"]
        )

    def test_macrodefin_requires_no_args(self) -> None:
        """Test that MacroDefIn can be instantiated without arguments."""
        # MacroDef is instantiated without args in MacroMapFileIn validator
        assert MacroDefIn()


class TestPlainMacroResolve:
    """Tests for plain (non-regex, non-template) macro resolution."""

    def test_resolve_first_single(self, macro_map: PropertyMacroMapping):
        # Single value for plain macro
        assert macro_map.get_macros(["pizza"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.PLAIN_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.PLAIN_MACRO}"),
                    value="pizza value",
                    description="Macro description",
                )
            }
        )

    def test_resolve_first_picks_alphabetical_first(
        self, macro_map: PropertyMacroMapping
    ):
        # Multiple values for resolve=first macro - should not combine, since it's not a regex macro
        assert macro_map.get_macros(["pizza", "barry"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.PLAIN_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.PLAIN_MACRO}"),
                    value="barry value",
                    description="Macro description",
                )
            }
        )

    def test_resolve_last_single(
        self,
        macro_map: PropertyMacroMapping,
    ):
        # Single value for resolve=last macro
        assert macro_map.get_macros(["tier_m"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.LAST_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"),
                    value="tier_m value",
                )
            }
        )

    def test_resolve_last_picks_alphabetical_last(
        self,
        macro_map: PropertyMacroMapping,
    ):
        # Multiple values for resolve=last macro - should pick the alphabetically last property
        assert macro_map.get_macros(
            ["tier_a", "tier_m", "tier_z"], DEFAULT_FACTS
        ) == snapshot(
            {
                "{$ZAC.LAST_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.LAST_MACRO}"),
                    value="tier_z value",
                )
            }
        )

    def test_resolve_last_inline_yaml(self, tmp_path: Path):
        """`resolve: last` picks alphabetically last contributing property."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.LAST_MACRO}":
    resolve: last
    properties:
      apple: "apple value"
      banana: "banana value"
      cherry: "cherry value"
""",
        )

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


class TestRegexMacroResolve:
    """Tests for regex macro resolution and deduplication."""

    def test_single_value(self, macro_map: PropertyMacroMapping):
        # Single value for macro with regex support
        assert macro_map.get_macros(["bazinga"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"), value="bazinga"
                )
            }
        )

    def test_multiple_values_combined(self, macro_map: PropertyMacroMapping):
        # Multiple values for macro with regex support
        assert macro_map.get_macros(["bazinga", "grok"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"),
                    value="(^grok value$|bazinga)",
                )
            }
        )

    def test_dedup_plain_values(self, tmp_path: Path):
        """Test deduplication of plain text values for regex macros."""
        m = _load_mapping(
            tmp_path,
            r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      default_db: postgresql
      is_pgsql_server: postgresql
      zabbix_agent: zabbix-agent
""",
        )

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

    def test_dedup_regex_patterns(self, tmp_path: Path):
        m = _load_mapping(
            tmp_path,
            r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      default_db: ^postgresql(\d+)?$
      is_pgsql_server: ^postgresql(\d+)?$
      zabbix_agent: ^zabbix-agent(\d+)?$
""",
        )

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

    def test_dedup_mixed(self, tmp_path: Path):
        """Test deduplication of mixed plain text and regex values for regex macros."""
        m = _load_mapping(
            tmp_path,
            r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      default_db: postgresql
      is_pgsql_server: postgresql
      zabbix_agent: ^zabbix-agent(\d+)?$

""",
        )

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

    def test_combined_pattern_validity(self, tmp_path: Path):
        """Test that the generated regex patterns are valid and correctly combined."""
        m = _load_mapping(
            tmp_path,
            r"""
macros:
  "{$SYSTEMD.NAME.SERVICE.MATCHES}":
    resolve: regex
    properties:
      is_pgsql_server: ^postgresql(\d+)?$
      zabbix_agent: ^zabbix-agent(\d+)?$
      use_zabbix_agent2: ^zabbix-agent2$
""",
        )

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


class TestContextMacro:
    """Tests for macros with text and regex contexts."""

    def test_text_context(self, macro_map: PropertyMacroMapping):
        # Macros with text context
        assert macro_map.get_macros(["foo"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.OPTIONAL_CONTEXT:/tmp}": ResolvedMacro(
                    identity=MacroIdentity(
                        name="{$ZAC.OPTIONAL_CONTEXT}", context="/tmp"
                    ),
                    value="30",
                    description="Description for /tmp context used here",
                )
            }
        )

    def test_regex_context(self, macro_map: PropertyMacroMapping):
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

    def test_text_and_regex_contexts(self, macro_map: PropertyMacroMapping):
        # Macros with two different contexts (text and regex)
        assert macro_map.get_macros(["foo", "bar"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.OPTIONAL_CONTEXT:/tmp}": ResolvedMacro(
                    identity=MacroIdentity(
                        name="{$ZAC.OPTIONAL_CONTEXT}", context="/tmp"
                    ),
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

    def test_multiple_regex_contexts_resolve_first(
        self, macro_map: PropertyMacroMapping
    ):
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

    def test_invalid_regex_context_rejected(self, tmp_path: Path):
        """Context macro with type `regex` that has invalid regex pattern."""
        with pytest.raises(
            ValidationError, match=re.escape("Invalid regex context: '[invalid('")
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.CONTEXT_MACRO}":
    resolve: first
    contexts:
      - context: "[invalid("
        context_type: regex
        description: "Regex context description"
        properties:
          foo: "[also_invalid(" # the context validation fails before this
""",
            )

    def test_context_with_template(self, tmp_path: Path):
        """Context macros must not use `resolve: regex`."""
        m = _load_mapping(
            tmp_path,
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
        )
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

    def test_context_overrides_template(self, tmp_path: Path):
        """Context macro with template and contexts that override template + placeholders."""
        m = _load_mapping(
            tmp_path,
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
        )
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

    def test_context_template_rejects_resolve_regex(self, tmp_path: Path):
        """Context macros with templates must not use `resolve: regex`."""
        with pytest.raises(
            ValidationError,
            match=re.escape("uses template; parent must not use resolve=regex"),
        ):
            _ = _load_mapping(
                tmp_path,
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
            )


class TestTemplateMacro:
    """Tests for template-based macro resolution."""

    def test_only_host_facts(self, macro_map: PropertyMacroMapping):
        # Test simple templated macro with no extra values - just host facts
        assert macro_map.get_macros(["dashboard_node"], DEFAULT_FACTS) == snapshot(
            {
                "{$ZAC.BASIC_TEMPLATE_MACRO}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.BASIC_TEMPLATE_MACRO}"),
                    value="https://grafana.example.com/d/node?var-host=testhost.example.com",
                )
            }
        )

    def test_default_placeholder(self, macro_map: PropertyMacroMapping):
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

    def test_per_property_value_override(self, macro_map: PropertyMacroMapping):
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

    def test_resolve_first_with_overrides(self, macro_map: PropertyMacroMapping):
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

    def test_per_property_template_same_placeholders(
        self, macro_map: PropertyMacroMapping
    ):
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

    def test_per_property_template_new_placeholders(
        self,
        macro_map: PropertyMacroMapping,
    ):
        """Test templated macro with properties that override the template and values on a per-property basis."""
        assert macro_map.get_macros(
            ["older_legacy_ingestor"], DEFAULT_FACTS
        ) == snapshot(
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

    def test_with_text_context(self, macro_map: PropertyMacroMapping):
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

    def test_with_regex_context(self, macro_map: PropertyMacroMapping):
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

    def test_unused_placeholder_value_ignored(self, tmp_path: Path) -> None:
        """Test passing in incorrect placeholder to a property of a template macro.

        NOTE
        ----
        Currently we don't flag this as an error, since the property simply
        inherits the missing value from the defaults when resolved.
        The incorrect placeholder is simply ignored.
        """
        m = _load_mapping(
            tmp_path,
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
        )
        macros = m.get_macros(["foo"], DEFAULT_FACTS)
        assert len(macros) == 1
        assert (
            # Macro inherits the missing `endpoint` value from defaults
            # while `wrong_placeholder` is ignored.
            macros["{$ZAC.TEMPLATE_UNUSED_VALUE}"].value
            == "https://testhost.example.com:910/ingestion"
        )

    def test_no_defaults_no_properties_ok(self, tmp_path: Path) -> None:
        """Template macro with no properties doesn't need defaults (no properties to validate)"""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.TEMPLATE_NO_PROPS}":
    template: "https://{{hostname}}:{{port}}/{{endpoint}}"
""",
        )  # reads fine
        assert len(m.definitions) == 1

    def test_no_defaults_with_properties_rejected(self, tmp_path: Path) -> None:
        """Template macro with properties must have defaults to satisfy placeholders."""
        with pytest.raises(
            ValidationError,
            match=re.escape(
                "Template placeholders not satisfied: {'foo': ['endpoint', 'port']}"
            ),
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.TEMPLATE_PROPS_NO_DEFAULTS}":
    template: "https://{{hostname}}:{{port}}/{{endpoint}}"
    properties:
      foo:
""",
            )

        with pytest.raises(
            ValidationError,
            match=re.escape(
                "Template placeholders not satisfied: {'monitored_node': ['port']}"
            ),
        ):
            _ = _load_mapping(
                tmp_path,
                """
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
            )

    def test_incomplete_defaults_rejected(self, tmp_path: Path):
        """Test that template macros without a complete `defaults` section fails."""
        with pytest.raises(
            ValidationError,
            match=re.escape(
                "Template placeholders not satisfied: {'monitored_node': ['endpoint'], 'legacy_exporter': ['endpoint']}"
            ),
        ):
            _ = _load_mapping(
                tmp_path,
                """
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
            )

    def test_rejects_resolve_regex(self, tmp_path: Path):
        """Template macros must not use `resolve: regex`."""
        with pytest.raises(
            ValidationError,
            match=re.escape("template macros do not support resolve=regex"),
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.TEMPLATE_MACRO}":
    resolve: regex
    template: "https://{{hostname}}/x"
    properties:
      foo:
""",
            )

    def test_property_template_without_parent_rejected(
        self,
        tmp_path: Path,
    ) -> None:
        """Macro where top-level macro does not define template, but its properties do. Forbid this."""
        with pytest.raises(
            ValidationError,
            match=re.escape(
                "Properties ['foo'] define templates but macro definition does not"
            ),
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.ONLY_PROPERTY_HAS_TEMPLATE}":
    description: "Ingestion endpoint"
    properties:
      foo:
        template: "https://{{hostname}}:{{port}}/{{endpoint}}"
        values:
            # missing port
            # but parent missing template is the error that will be raised
            endpoint: ingestion

""",
            )

    def test_property_values_without_template_rejected(
        self,
        tmp_path: Path,
    ) -> None:
        """Macro where top-level macro does not define template, but its property defines `values`."""
        with pytest.raises(
            ValidationError,
            match=re.escape(
                "Properties have `values` keys but no template defined: {'foo': ['port', 'endpoint']}"
            ),
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.NO_TEMPLATE_PROPERTY_HAS_VALUES}":
    description: "Ingestion endpoint"
    properties:
      foo:
        value: "some value" # checked before `values`, so must be present to trigger error
        values:
          port: 9001
          endpoint: ingestion

""",
            )

    def test_empty_string_template_toplevel_allowed(
        self,
        tmp_path: Path,
    ) -> None:
        """Macro where top-level macro has empty string template.

        Correctly resolves to an empty value.
        We assume the use of an empty string is deliberate.
        """
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.TEMPLATE_EMPTY_STRING}":
    description: "Ingestion endpoint"
    template: ""
    properties:
      foo:
        values:
          port: 9001
          endpoint: ingestion
""",
        )

        macros = m.get_macros(["foo"], DEFAULT_FACTS)
        assert macros == snapshot(
            {
                "{$ZAC.TEMPLATE_EMPTY_STRING}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.TEMPLATE_EMPTY_STRING}"),
                    value="",
                    description="Ingestion endpoint",
                )
            }
        )

    def test_empty_string_template_property_allowed(
        self,
        tmp_path: Path,
    ) -> None:
        """Macro where property overrides with empty string template.

        FIXME
        -----
        Due to technical reasons, the property inherits the template
        from the parent definition. This has to do with the way we
        evaluate template 'inheritance' on runtime when resolving macros.

        Ideally, we would be consistent with our `None` checks and treat
        empty strings as semantically different from `None` everywhere, but
        don't actually do that today because of all the `x or y` evaluations,
        which means if `x == ""`, it's semantically identical to `None`.
        """
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.TEMPLATE_PROPERTY_EMPTY_STRING}":
    description: "Ingestion endpoint"
    template: "https://{{hostname}}:{{port}}/{{endpoint}}"
    defaults:
      port: 9001
      endpoint: ingestion
    properties:
      foo:
        template: "" # will not be used!
""",
        )

        # Resolves to parent macro - ideally the value would be an empty string
        macros = m.get_macros(["foo"], DEFAULT_FACTS)
        assert macros == snapshot(
            {
                "{$ZAC.TEMPLATE_PROPERTY_EMPTY_STRING}": ResolvedMacro(
                    identity=MacroIdentity(
                        name="{$ZAC.TEMPLATE_PROPERTY_EMPTY_STRING}"
                    ),
                    value="https://testhost.example.com:9001/ingestion",
                    description="Ingestion endpoint",
                )
            }
        )

    def test_full_combo(self, tmp_path: Path):
        """Macro with template, contexts and host overrides."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.TEMPLATE_AND_CONTEXT}":
    template: "https://{{hostname}}:{{port}}/ctx/{{ctx}}"
    resolve: first
    defaults:
      port: 9100
      ctx: defaultctx
    properties:
      spam:
    hosts:
      barhost.example.com:
        values:
          port: 9200
          ctx: barhostctx
      ".*.example.com": # regex match (matched if no exact match)
        values:
          port: 9300
          ctx: regexhostctx
      testhost.example.com: # exact match (preferred)
        values:
          port: 9400
          ctx: testhostctx
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
        )
        facts = HostFacts(hostname="testhost.example.com")

        # Matches on spam and hostname -> hostname match used
        assert m.get_macros(["spam"], facts) == snapshot(
            {
                "{$ZAC.TEMPLATE_AND_CONTEXT}": ResolvedMacro(
                    identity=MacroIdentity(name="{$ZAC.TEMPLATE_AND_CONTEXT}"),
                    value="https://testhost.example.com:9400/ctx/testhostctx",
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


class TestHostOverride:
    """Tests for per-host macro value overrides."""

    def test_exact_match_wins_over_property(self, tmp_path: Path) -> None:
        """Exact hostname match overrides property-derived value."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_OVR}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    properties:
      foo:
    hosts:
      testhost.example.com:
        values:
          port: 9999
""",
        )
        macros = m.get_macros(["foo"], DEFAULT_FACTS)
        assert macros["{$ZAC.HOST_OVR}"].value == "https://testhost.example.com:9999/x"

    def test_regex_fallback_when_no_exact(self, tmp_path: Path) -> None:
        """Regex hostname match used when no exact match exists."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_OVR}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    properties:
      foo:
    hosts:
      ".*\\\\.example\\\\.com":
        values:
          port: 9200
""",
        )
        macros = m.get_macros(["foo"], HostFacts(hostname="other.example.com"))
        assert macros["{$ZAC.HOST_OVR}"].value == "https://other.example.com:9200/x"

    def test_longest_regex_wins(self, tmp_path: Path) -> None:
        """When multiple regex patterns match, longest pattern wins."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_OVR}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    properties:
      foo:
    hosts:
      ".*":
        values:
          port: 9001
      ".*\\\\.example\\\\.com":
        values:
          port: 9002
""",
        )
        macros = m.get_macros(["foo"], HostFacts(hostname="x.example.com"))
        assert macros["{$ZAC.HOST_OVR}"].value == "https://x.example.com:9002/x"

    def test_alphabetical_tiebreak(self, tmp_path: Path) -> None:
        """Regex patterns of equal length tie-break alphabetically."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_OVR}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    properties:
      foo:
    hosts:
      "z.*\\\\.example\\\\.com":
        values:
          port: 9999
      "a.*\\\\.example\\\\.com":
        values:
          port: 9000
""",
        )
        macros = m.get_macros(["foo"], HostFacts(hostname="aaa.example.com"))
        assert macros["{$ZAC.HOST_OVR}"].value == "https://aaa.example.com:9000/x"

    def test_only_host_emits_when_match(self, tmp_path: Path) -> None:
        """Host match alone (no property) is enough to emit the macro."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_ONLY}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    hosts:
      testhost.example.com:
        values:
          port: 7777
""",
        )
        macros = m.get_macros([], DEFAULT_FACTS)
        assert macros["{$ZAC.HOST_ONLY}"].value == "https://testhost.example.com:7777/x"

    def test_only_host_does_not_emit_when_no_match(self, tmp_path: Path) -> None:
        """No host match and no property contribution → macro not emitted."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_ONLY}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    hosts:
      other.example.com:
        values:
          port: 7777
""",
        )
        macros = m.get_macros([], DEFAULT_FACTS)
        assert "{$ZAC.HOST_ONLY}" not in macros

    def test_in_context_scoped_to_that_context(self, tmp_path: Path) -> None:
        """Per-context hosts apply only to that context's macro identity."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_CTX}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    properties:
      foo:
    contexts:
      - context: "ctxA"
        properties:
          foo:
        hosts:
          testhost.example.com:
            values:
              port: 1111
      - context: "ctxB"
        properties:
          foo:
""",
        )
        macros = m.get_macros(["foo"], DEFAULT_FACTS)
        assert macros["{$ZAC.HOST_CTX}"].value == "https://testhost.example.com:9100/x"
        assert (
            macros["{$ZAC.HOST_CTX:ctxA}"].value
            == "https://testhost.example.com:1111/x"
        )
        assert (
            macros["{$ZAC.HOST_CTX:ctxB}"].value
            == "https://testhost.example.com:9100/x"
        )

    def test_template_override(self, tmp_path: Path) -> None:
        """Per-host template override takes precedence when host matches."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.HOST_TPL}":
    template: "https://{{hostname}}:{{port}}/default"
    defaults:
      port: 9100
    properties:
      foo:
    hosts:
      testhost.example.com:
        template: "https://{{hostname}}:{{port}}/overridden"
        values:
          port: 8888
""",
        )
        macros = m.get_macros(["foo"], DEFAULT_FACTS)
        assert (
            macros["{$ZAC.HOST_TPL}"].value
            == "https://testhost.example.com:8888/overridden"
        )

    def test_scalar_under_template_rejected(self, tmp_path: Path) -> None:
        """Host scalar shorthand forbidden when parent has template (mirrors property rule)."""
        with pytest.raises(
            ValidationError,
            match=re.escape("Host 'testhost.example.com' uses scalar shorthand"),
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.BAD}":
    template: "https://{{hostname}}:{{port}}/x"
    defaults:
      port: 9100
    properties:
      foo:
    hosts:
      testhost.example.com: "scalar"
""",
            )

    def test_unsatisfied_placeholders_rejected(self, tmp_path: Path) -> None:
        """Host that doesn't satisfy template placeholders raises."""
        with pytest.raises(
            ValidationError,
            match=re.escape("Template placeholders not satisfied"),
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.BAD}":
    template: "https://{{hostname}}:{{port}}/{{missing}}"
    defaults:
      port: 9100
    hosts:
      testhost.example.com:
""",
            )

    def test_invalid_regex_key_rejected(self, tmp_path: Path) -> None:
        """Hostname keys must compile as regex."""
        with pytest.raises(ValidationError, match=re.escape("Invalid host pattern")):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$ZAC.BAD}":
    template: "https://{{hostname}}/x"
    properties:
      foo:
    hosts:
      "[unclosed":
        values: {}
""",
            )

    def test_wins_over_resolve_regex(self, tmp_path: Path) -> None:
        """resolve=regex with a host match: host wins, regex union is bypassed."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.RX_HOST}":
    resolve: regex
    properties:
      foo: "fooval"
      bar: "barval"
    hosts:
      testhost.example.com: "hostval"
""",
        )
        macros = m.get_macros(["foo", "bar"], DEFAULT_FACTS)
        assert macros["{$ZAC.RX_HOST}"].value == "hostval"

    def test_overrides_property_for_plain_macro(self, tmp_path: Path) -> None:
        """Plain (non-template) macro: host scalar overrides property scalar."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.PLAIN}":
    properties:
      foo: "fooval"
    hosts:
      testhost.example.com: "hostval"
""",
        )
        macros = m.get_macros(["foo"], DEFAULT_FACTS)
        assert macros["{$ZAC.PLAIN}"].value == "hostval"

    def test_patterns_compiled_lazily_and_cached(self, tmp_path: Path) -> None:
        """`host_patterns` is a cached_property: same list on repeat access; sort order checked."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$ZAC.CACHE}":
    template: "https://{{hostname}}/x"
    properties:
      foo:
    hosts:
      ".*\\\\.example\\\\.com":
        values: {}
      "z.*":
        values: {}
""",
        )
        defn = m.definitions[0]
        first = defn.host_patterns
        second = defn.host_patterns
        assert first is second
        assert [k for _, k in first] == [".*\\.example\\.com", "z.*"]


class TestPropertyValues:
    """Tests for property value handling (empty, null, whitespace)."""

    def test_empty_string_accepted(self, tmp_path: Path):
        """Test that properties with empty string values are accepted and can be resolved."""
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$BLANK_PROPERTIES}":
    properties:
      default_db: xyzzydb  # ensures we sort by property value, not macro value
      is_pgsql_server: ""
""",
        )
        assert m.get_macros(["is_pgsql_server"], DEFAULT_FACTS) == snapshot(
            {
                "{$BLANK_PROPERTIES}": ResolvedMacro(
                    identity=MacroIdentity(name="{$BLANK_PROPERTIES}"), value=""
                )
            }
        )

        # alphabetically first property
        assert m.get_macros(
            ["default_db", "is_pgsql_server"], DEFAULT_FACTS
        ) == snapshot(
            {
                "{$BLANK_PROPERTIES}": ResolvedMacro(
                    identity=MacroIdentity(name="{$BLANK_PROPERTIES}"), value="xyzzydb"
                )
            }
        )

    def test_null_rejected(self, tmp_path: Path):
        """Test that properties with null values are rejected.

        Using an empty macro value should be a deliberate choice denoted
        by an empty string literal - not the absence of a value."""
        with pytest.raises(
            ValidationError,
            match=re.escape("Property values cannot be null: ['is_pgsql_server']"),
        ):
            _ = _load_mapping(
                tmp_path,
                """
macros:
  "{$BLANK_PROPERTIES}":
    properties:
      default_db: xyzzydb
      is_pgsql_server:
""",
            )

    def test_whitespace_preserved(self, tmp_path: Path):
        """Test leading/trailing/only whitespace in property values is preserved.

        Ensures we catch if we change this behavior in the future.
        We can't assume anything about what whitespace denotes in macro values.
        It is very difficult to unintentionally add leading/trailing whitespace in YAML,
        so it's unlikely that this would happen by mistake.

        If it's present, it's probably intentional, and we should preserve it.
        """
        m = _load_mapping(
            tmp_path,
            """
macros:
  "{$WHITESPACE_VALUES}":
    properties:
      default_db: " maindb"  # leading
      alternate_db: "altdb "  # trailing
      is_pgsql_server: "   " # only whitespace
""",
        )
        assert m.get_macros(["default_db"], DEFAULT_FACTS) == snapshot(
            {
                "{$WHITESPACE_VALUES}": ResolvedMacro(
                    identity=MacroIdentity(name="{$WHITESPACE_VALUES}"), value=" maindb"
                )
            }
        )
        assert m.get_macros(["alternate_db"], DEFAULT_FACTS) == snapshot(
            {
                "{$WHITESPACE_VALUES}": ResolvedMacro(
                    identity=MacroIdentity(name="{$WHITESPACE_VALUES}"), value="altdb "
                )
            }
        )
        assert m.get_macros(["is_pgsql_server"], DEFAULT_FACTS) == snapshot(
            {
                "{$WHITESPACE_VALUES}": ResolvedMacro(
                    identity=MacroIdentity(name="{$WHITESPACE_VALUES}"), value="   "
                )
            }
        )


class TestSpecialValueTypes:
    """Tests for secret and vault macro value types."""

    def test_secret(self, macro_map: PropertyMacroMapping):
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

    def test_vault(self, macro_map: PropertyMacroMapping):
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


class TestSubstitutions:
    """Tests for template placeholder substitution logic."""

    def test_get_substitutions_per_property(self, tmp_path: Path) -> None:
        """Test `get_substitutions using a macro with template+template override in properties."""
        m = _load_mapping(
            tmp_path,
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
        )
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

    def test_builtin_placeholder_keys_snapshot(self) -> None:
        """Snapshot test to catch changes to builtin placeholder keys (host facts, resolved macro properties, etc.)"""
        assert BUILTIN_PLACEHOLDERS == snapshot(frozenset({"hostname", "property"}))

    def test_builtin_keys_used_in_example_mapping(
        self,
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
                    expect = (
                        BUILTIN_PLACEHOLDERS | set(macro.defaults) | set(prop.values)
                    )
                    assert expect.issubset(subs.keys())


class TestHostFacts:
    def test_get_host_facts(self) -> None:
        assert get_host_facts(
            Host(
                enabled=True,
                hostname="mytesthost.example.com",
                importance=5,
                interfaces=[
                    Interface(
                        endpoint="mytesthost.example.com",
                        port="10050",
                        type=1,
                    ),
                    Interface(
                        endpoint="mytesthost.example.com",
                        port="161",
                        type=2,
                        details={"version": 2, "community": "{$SNMP_COMMUNITY}"},
                    ),
                ],
                inventory={"OS": "Linux"},
                macros=None,  # unused, will be removed - not synced
                properties={"foo", "bar", "baz"},
                proxy_pattern=r"^zbx-proxy\d+\.example\.com$",
                siteadmins={"alice@example.com", "bob@example.com"},
                sources={"source1", "source2"},
                tags={("tag1", "x"), ("tag2", "y")},
            )
        ) == snapshot({"hostname": "mytesthost.example.com"})
