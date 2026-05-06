from __future__ import annotations

from pathlib import Path

import pytest
from inline_snapshot import snapshot
from zabbix_auto_config.macros import ContextType
from zabbix_auto_config.macros import MacroIdentity
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


# Read example mapping file so we know our examples
# are always up-to-date and are valid.
SAMPLE_PROPERTY_MACRO_MAP = (
    Path(__file__).parent.parent
    / "example"
    / "mapping_files"
    / "property_macro_map.yaml"
).read_text(encoding="utf-8")


@pytest.fixture(scope="function")
def sample_property_macro_map_path(tmp_path: Path):
    """Creates a sample property macro map file for testing."""
    p = tmp_path / "property_macro_map.yaml"
    p.write_text(SAMPLE_PROPERTY_MACRO_MAP, encoding="utf-8")
    yield p


def test_read_property_macro_map(sample_property_macro_map_path: Path):
    m = read_property_macro_map(sample_property_macro_map_path)

    # Dump internal representation of the property macro map
    assert m.model_dump_json(indent=2) == snapshot("""\
{
  "definitions": [
    {
      "identity": {
        "name": "{$ZAC.TEXT_MACRO}",
        "context": null,
        "context_type": "static"
      },
      "description": null,
      "macro_type": "text",
      "combine": "text",
      "properties": {
        "barry": {
          "value": "barry value",
          "description": null
        },
        "pizza": {
          "value": "pizza value",
          "description": null
        },
        "spam": {
          "value": "spam value",
          "description": null
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
      "macro_type": "text",
      "combine": "regex",
      "properties": {
        "spam": {
          "value": "spam value",
          "description": null
        },
        "baz": {
          "value": "bazinga",
          "description": null
        },
        "grok": {
          "value": "^grok value$",
          "description": "We can override the description for individual properties as well"
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
      "macro_type": "text",
      "combine": "text",
      "properties": {
        "spam": {
          "value": "value for non-context spam",
          "description": null
        },
        "eggs": {
          "value": "value for non-context eggs",
          "description": null
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
      "macro_type": "text",
      "combine": "text",
      "properties": {
        "spam": {
          "value": "20",
          "description": null
        },
        "foo": {
          "value": "30",
          "description": null
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
      "macro_type": "text",
      "combine": "text",
      "properties": {
        "spam": {
          "value": "30",
          "description": null
        },
        "bar": {
          "value": "40",
          "description": null
        },
        "gux": {
          "value": "50",
          "description": null
        }
      }
    }
  ]
}\
""")


def test_property_macro_map_get_macros(sample_property_macro_map_path: Path):
    m = read_property_macro_map(sample_property_macro_map_path)

    # Single value for regular non-regex macro
    assert m.get_macros(["pizza"]) == snapshot(
        {
            "{$ZAC.TEXT_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.TEXT_MACRO}"), value="pizza value"
            )
        }
    )

    # Multiple values for regular non-regex macro - should not combine, since it's not a regex macro
    assert m.get_macros(["pizza", "barry"]) == snapshot(
        {
            "{$ZAC.TEXT_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.TEXT_MACRO}"), value="barry value"
            )
        }
    )

    # Single value for macro with regex support
    assert m.get_macros(["baz"]) == snapshot(
        {
            "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"),
                value="bazinga",
                description="This one has a description!",
            )
        }
    )

    # Multiple values for macro with regex support
    assert m.get_macros(["baz", "grok"]) == snapshot(
        {
            "{$ZAC.REGEX_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.REGEX_MACRO}"),
                value="(^grok value$|bazinga)",
                description="We can override the description for individual properties as well",
            )
        }
    )
    # Macros with text context
    assert m.get_macros(["foo"]) == snapshot(
        {
            "{$ZAC.OPTIONAL_CONTEXT:/tmp}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.OPTIONAL_CONTEXT}", context="/tmp"),
                value="30",
                description="Description for /tmp context used here",
            )
        }
    )
    # Macros with regex context
    assert m.get_macros(["bar"]) == snapshot(
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
    # Macros with two different contexts (text and regex)
    assert m.get_macros(["foo", "bar"]) == snapshot(
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
    # Macros with two regex contexts with different values for a text macro
    # (alphabetically first is chosen -> "bar" chosen over "gux")
    assert m.get_macros(["bar", "gux"]) == snapshot(
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

    # Combine everything
    assert m.get_macros(
        [
            "pizza",
            "barry",
            "spam",
            "eggs",
            "ham",
            "grok",
            "foo",
            "bar",
            "baz",
        ]
    ) == snapshot(
        {
            "{$ZAC.TEXT_MACRO}": ResolvedMacro(
                identity=MacroIdentity(name="{$ZAC.TEXT_MACRO}"), value="barry value"
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
                value="20",
                description="Description for /tmp context used here",
            ),
            '{$ZAC.OPTIONAL_CONTEXT:regex:"^/var/log/.*$"}': ResolvedMacro(
                identity=MacroIdentity(
                    name="{$ZAC.OPTIONAL_CONTEXT}",
                    context="^/var/log/.*$",
                    context_type=ContextType.REGEX,
                ),
                value="30",
                description="This macro has contexts, but is optional",
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
    combine: regex
    properties:
      default_db: postgresql
      is_pgsql_server: postgresql
      zabbix_agent: zabbix-agent
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Resolve to single value
    macros = m.get_macros(["default_db", "is_pgsql_server"])
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
    macros = m.get_macros(["default_db", "is_pgsql_server", "zabbix_agent"])
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
    combine: regex
    properties:
      default_db: ^postgresql(\d+)?$
      is_pgsql_server: ^postgresql(\d+)?$
      zabbix_agent: ^zabbix-agent(\d+)?$
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Test that duplicate values are deduplicated for regex macros
    macros = m.get_macros(["default_db", "is_pgsql_server", "zabbix_agent"])
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
    combine: regex
    properties:
      default_db: postgresql
      is_pgsql_server: postgresql
      zabbix_agent: ^zabbix-agent(\d+)?$

""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Test that duplicate values are deduplicated for regex macros
    macros = m.get_macros(["default_db", "is_pgsql_server"])
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
    combine: regex
    properties:
      is_pgsql_server: ^postgresql(\d+)?$
      zabbix_agent: ^zabbix-agent(\d+)?$
      use_zabbix_agent2: ^zabbix-agent2$
""",
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Combinations of regex patterns
    macros = m.get_macros(["is_pgsql_server", "zabbix_agent"])
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="(^postgresql(\\d+)?$|^zabbix-agent(\\d+)?$)",
            )
        }
    )
    assert contains_valid_regex(macros)

    macros = m.get_macros(["zabbix_agent", "use_zabbix_agent2"])
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
    macros = m.get_macros(["zabbix_agent"])
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="^zabbix-agent(\\d+)?$",
            )
        }
    )
    assert contains_valid_regex(macros)

    macros = m.get_macros(["use_zabbix_agent2"])
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="^zabbix-agent2$",
            )
        }
    )
    assert contains_valid_regex(macros)

    macros = m.get_macros(["is_pgsql_server"])
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": ResolvedMacro(
                identity=MacroIdentity(name="{$SYSTEMD.NAME.SERVICE.MATCHES}"),
                value="^postgresql(\\d+)?$",
            )
        }
    )
    assert contains_valid_regex(macros)
