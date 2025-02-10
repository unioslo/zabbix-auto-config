from __future__ import annotations

import pytest
from inline_snapshot import snapshot
from pydantic import ValidationError
from zabbix_auto_config.db import parse_postgres_uri


def test_parse_postgres_uri_default():
    """Test that we can parse a PostgreSQL connection string as specified in sample config."""
    params = parse_postgres_uri(
        "dbname='zac' user='zabbix' host='localhost' password='secret' port=5432 connect_timeout=2"
    )

    assert params.model_dump(mode="json") == snapshot(
        {
            "dbname": "zac",
            "user": "zabbix",
            "host": "localhost",
            "password": "secret",
            "port": 5432,
            "connect_timeout": 2,
        }
    )


def test_parse_postgres_uri_no_optional_args():
    """Test that we can parse a PostgreSQL connection string with optional args omitted."""
    params = parse_postgres_uri(
        "dbname='zac' user='zabbix' host='localhost' password='secret'"
    )

    assert params.model_dump(mode="json") == snapshot(
        {
            "dbname": "zac",
            "user": "zabbix",
            "host": "localhost",
            "password": "secret",
            "port": 5432,
            "connect_timeout": None,
        }
    )


def test_parse_postgres_uri_missing_required_arg():
    """Test that we can parse a PostgreSQL connection string with optional args omitted."""

    with pytest.raises(ValidationError) as excinfo:
        parse_postgres_uri("dbname='zac' user='zabbix' password='secret'")

    assert str(
        excinfo.value.errors(include_url=False, include_context=False)
    ) == snapshot(
        "[{'type': 'value_error', 'loc': ('host',), 'msg': 'Value error, Postgres connection info missing host', 'input': None}]"
    )
