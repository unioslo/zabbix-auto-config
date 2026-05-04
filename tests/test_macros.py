from __future__ import annotations

from pathlib import Path

import pytest
import structlog
from inline_snapshot import snapshot
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


SAMPLE_PROPERTY_MACRO_MAP = """\
macros:
  "{$OS}": # non-regex macro with multiple properties
    description: "Operating system identifier" # custom description
    properties:
      os_linux: Linux
      os_bsd:
        value: BSD
        description: "BSD override"

  "{$SPAM}": # regex macro with multiple properties
    combine: regex
    properties:
      foo_prop: spam_val_1
      bar_prop: spam_val_2

  "{$LOW_SPACE_LIMIT}": # Contains macros with contexts
    description: "Low disk space % threshold"
    properties:
      role_default: 10
    contexts:
      - context: "/tmp"
        properties:
          role_app: 20
      - context: "^/var/log/.*$"
        context_type: regex
        combine: regex
        properties:
          baz_prop: 30
          gux_prop: 40
"""


@pytest.fixture(scope="function")
def sample_property_macro_map_path(tmp_path: Path):
    """Creates a sample property macro map file for testing."""
    p = tmp_path / "property_macro_map.yaml"
    p.write_text(SAMPLE_PROPERTY_MACRO_MAP, encoding="utf-8")
    yield p


def test_read_property_macro_map(
    tmp_path: Path, log_output: structlog.testing.LogCapture
):
    tmpfile = tmp_path / "property_macro_map.txt"
    tmpfile.write_text(  # pyright: ignore[reportUnusedCallResult]
        SAMPLE_PROPERTY_MACRO_MAP,
        encoding="utf-8",
    )
    m = read_property_macro_map(tmpfile)

    # Dump internal representation of the property macro map
    assert m.model_dump_json(indent=2) == snapshot("""\
{
  "definitions": [
    {
      "identity": {
        "name": "{$OS}",
        "context": null,
        "context_type": "static"
      },
      "description": "Operating system identifier",
      "macro_type": "text",
      "combine": "text",
      "properties": {
        "os_linux": {
          "value": "Linux",
          "description": null
        },
        "os_bsd": {
          "value": "BSD",
          "description": "BSD override"
        }
      }
    },
    {
      "identity": {
        "name": "{$SPAM}",
        "context": null,
        "context_type": "static"
      },
      "description": null,
      "macro_type": "text",
      "combine": "regex",
      "properties": {
        "foo_prop": {
          "value": "spam_val_1",
          "description": null
        },
        "bar_prop": {
          "value": "spam_val_2",
          "description": null
        }
      }
    },
    {
      "identity": {
        "name": "{$LOW_SPACE_LIMIT}",
        "context": null,
        "context_type": "static"
      },
      "description": "Low disk space % threshold",
      "macro_type": "text",
      "combine": "text",
      "properties": {
        "role_default": {
          "value": "10",
          "description": null
        }
      }
    },
    {
      "identity": {
        "name": "{$LOW_SPACE_LIMIT}",
        "context": "/tmp",
        "context_type": "static"
      },
      "description": "Low disk space % threshold",
      "macro_type": "text",
      "combine": "text",
      "properties": {
        "role_app": {
          "value": "20",
          "description": null
        }
      }
    },
    {
      "identity": {
        "name": "{$LOW_SPACE_LIMIT}",
        "context": "^/var/log/.*$",
        "context_type": "regex"
      },
      "description": "Low disk space % threshold",
      "macro_type": "text",
      "combine": "regex",
      "properties": {
        "baz_prop": {
          "value": "30",
          "description": null
        },
        "gux_prop": {
          "value": "40",
          "description": null
        }
      }
    }
  ]
}\
""")


def test_property_macro_map_get_macros(sample_property_macro_map_path: Path):
    m = read_property_macro_map(sample_property_macro_map_path)
    assert m.get_macros(["os_linux"]) == snapshot(
        {
            "{$OS}": ResolvedMacro(
                identity=MacroIdentity(name="{$OS}"),
                value="Linux",
                description="Operating system identifier",
            )
        }
    )

    # Single value for regular non-regex macro
    assert m.get_macros(["os_linux"]) == snapshot(
        {
            "{$OS}": ResolvedMacro(
                identity=MacroIdentity(name="{$OS}"),
                value="Linux",
                description="Operating system identifier",
            )
        }
    )

    # Multiple values for regular non-regex macro - should not combine, since it's not a regex macro
    assert m.get_macros(["os_linux", "os_bsd"]) == snapshot(
        {
            "{$OS}": ResolvedMacro(
                identity=MacroIdentity(name="{$OS}"),
                value="BSD",
                description="BSD override",
            )
        }
    )

    # Single value for macro with regex support
    assert m.get_macros(["foo_prop"]) == snapshot(
        {
            "{$SPAM}": ResolvedMacro(
                identity=MacroIdentity(name="{$SPAM}"), value="spam_val_1"
            )
        }
    )

    # Multiple values for macro with regex support
    assert m.get_macros(["foo_prop", "bar_prop"]) == snapshot(
        {
            "{$SPAM}": ResolvedMacro(
                identity=MacroIdentity(name="{$SPAM}"), value="(spam_val_1|spam_val_2)"
            )
        }
    )


def test_property_macro_map_get_zabbix_macros(sample_property_macro_map_path: Path):
    m = read_property_macro_map(sample_property_macro_map_path)
    assert m.get_zabbix_macros(["os_linux"]) == snapshot(
        {
            "{$OS}": "Linux",
        }
    )
    assert m.get_zabbix_macros(["os_linux", "os_bsd"]) == snapshot(
        {
            "{$OS}": "BSD",
        }
    )
    assert m.get_zabbix_macros(["foo_prop", "bar_prop"]) == snapshot(
        {
            "{$SPAM}": "(spam_val_1|spam_val_2)",
        }
    )

    # Combine everything
    assert m.get_zabbix_macros(
        [
            "os_linux",
            "os_bsd",
            "foo_prop",
            "bar_prop",
            "role_default",
            "role_app",
            "gux_prop",
        ]
    ) == snapshot(
        {
            "{$OS}": "BSD",
            "{$SPAM}": "(spam_val_1|spam_val_2)",
            "{$LOW_SPACE_LIMIT}": "10",
            "{$LOW_SPACE_LIMIT:/tmp}": "20",
            '{$LOW_SPACE_LIMIT:regex:"^/var/log/.*$"}': "40",
        }
    )


def contains_valid_regex(macros: dict[str, str]) -> bool:
    """Ensure mapping contains valid regex patterns for all macros (if any)."""
    import re

    for macro, pattern in macros.items():
        try:
            re.compile(pattern)
        except re.error:
            pytest.fail(f"Invalid regex pattern for macro {macro}: {pattern}")
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
    macros = m.get_zabbix_macros(["default_db", "is_pgsql_server"])
    assert macros == snapshot({"{$SYSTEMD.NAME.SERVICE.MATCHES}": "postgresql"})
    assert contains_valid_regex(macros)

    # Resolve to simple OR regex pattern
    macros = m.get_zabbix_macros(["default_db", "is_pgsql_server", "zabbix_agent"])
    assert macros == snapshot(
        {"{$SYSTEMD.NAME.SERVICE.MATCHES}": "(postgresql|zabbix-agent)"}
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
    macros = m.get_zabbix_macros(["default_db", "is_pgsql_server", "zabbix_agent"])
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": "(^postgresql(\\d+)?$|^zabbix-agent(\\d+)?$)"
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
    macros = m.get_zabbix_macros(["default_db", "is_pgsql_server"])
    assert macros == snapshot({"{$SYSTEMD.NAME.SERVICE.MATCHES}": "postgresql"})
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
    macros = m.get_zabbix_macros(["is_pgsql_server", "zabbix_agent"])
    assert macros == snapshot(
        {
            "{$SYSTEMD.NAME.SERVICE.MATCHES}": "(^postgresql(\\d+)?$|^zabbix-agent(\\d+)?$)"
        }
    )
    assert contains_valid_regex(macros)

    macros = m.get_zabbix_macros(["zabbix_agent", "use_zabbix_agent2"])
    assert macros == snapshot(
        {"{$SYSTEMD.NAME.SERVICE.MATCHES}": "(^zabbix-agent(\\d+)?$|^zabbix-agent2$)"}
    )
    assert contains_valid_regex(macros)

    # Individual regex patterns
    macros = m.get_zabbix_macros(["zabbix_agent"])
    assert macros == snapshot(
        {"{$SYSTEMD.NAME.SERVICE.MATCHES}": "^zabbix-agent(\\d+)?$"}
    )
    assert contains_valid_regex(macros)

    macros = m.get_zabbix_macros(["use_zabbix_agent2"])
    assert macros == snapshot({"{$SYSTEMD.NAME.SERVICE.MATCHES}": "^zabbix-agent2$"})
    assert contains_valid_regex(macros)

    macros = m.get_zabbix_macros(["is_pgsql_server"])
    assert macros == snapshot(
        {"{$SYSTEMD.NAME.SERVICE.MATCHES}": "^postgresql(\\d+)?$"}
    )
    assert contains_valid_regex(macros)
