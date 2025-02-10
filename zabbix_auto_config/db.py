"""Database initialization using SQLAlchemy with JSONB columns.

Provides utilities to ensure a PostgreSQL database and its tables exist,
creating them if necessary. Uses JSONB columns for efficient JSON storage
and indexing capabilities.
"""

from __future__ import annotations

import re
from typing import Any
from typing import Dict
from typing import Optional

import sqlalchemy as sa
from pydantic import BaseModel
from pydantic import ValidationInfo
from pydantic import field_validator
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base
from sqlalchemy_utils import create_database
from sqlalchemy_utils import database_exists

Base = declarative_base()


DEFAULT_PORT = 5432


class PostgresConnectionParams(BaseModel):
    """Connection parameters for a PostgreSQL database.

    Attributes:
        dbname: Name of the database
        user: Username for authentication
        host: Database server hostname
        password: Password for authentication
        port: Port number (defaults to 5432)
        connect_timeout: Connection timeout in seconds (optional)
    """

    dbname: str
    user: str
    host: str
    password: str
    port: int = DEFAULT_PORT
    connect_timeout: int | None = None

    @field_validator("port", "connect_timeout", mode="before")
    @classmethod
    def _use_default_if_none(cls, value: Any, info: ValidationInfo) -> Any:
        """Fall back to field default if value is None"""
        if value is None:
            if info.field_name is None:  # why can this be None?
                raise ValueError(f"Failed to validate {info}")
            return cls.model_fields[info.field_name].default
        return value

    @field_validator("dbname", "user", "host", "password", mode="before")
    @classmethod
    def _required_field_has_none(cls, value: Any, info: ValidationInfo) -> Any:
        if value is None:
            raise ValueError(
                f"Postgres connection info missing {info.field_name or info}"
            )
        return value

    @classmethod
    def from_params(cls, params: Dict[str, Any]) -> PostgresConnectionParams:
        return cls(
            dbname=params.get("dbname"),  # pyright: ignore[reportArgumentType] # validator handles
            user=params.get("user"),  # pyright: ignore[reportArgumentType] # validator handles
            host=params.get("host"),  # pyright: ignore[reportArgumentType] # validator handles
            password=params.get("password"),  # pyright: ignore[reportArgumentType] # validator handles
            port=params.get("port", DEFAULT_PORT),
            connect_timeout=params.get("connect_timeout", None),
        )


class Hosts(Base):
    """Model for storing merged hosts."""

    __tablename__ = "hosts"

    id = sa.Column(sa.Integer, primary_key=True)
    data = sa.Column(JSONB)


class HostsSource(Base):
    """Model for storing source hosts."""

    __tablename__ = "hosts_source"

    id = sa.Column(sa.Integer, primary_key=True)
    data = sa.Column(JSONB)


def parse_postgres_uri(uri: str) -> PostgresConnectionParams:
    """Parse a PostgreSQL libpq connection string into structured parameters.

    Args:
        uri: A PostgreSQL connection string in libpq format
            (e.g., "dbname='mydb' user='user' host='localhost'")

    Returns:
        PostgresConnectionParams containing the parsed connection parameters

    Example:
        >>> params = parse_postgres_uri("dbname='mydb' user='user' host='localhost'")
        >>> print(params.dbname)
        'mydb'
    """
    # Pattern matches key='value' or key=value pairs
    pattern = r"(\w+)\s*=\s*(?:'([^']*)'|(\d+))"
    matches = re.findall(pattern, uri)

    # Combine quoted and unquoted values, preferring quoted
    params = {match[0]: match[1] or match[2] for match in matches}

    # Create NamedTuple with all required and optional fields
    return PostgresConnectionParams.from_params(params)


def init_db(
    *,
    uri: Optional[str] = None,
    db: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    password: Optional[str] = None,
    port: int = DEFAULT_PORT,
    timeout: Optional[int] = None,
) -> sa.Engine:
    """Initialize database and tables idempotently.

    A DB URI or individual parameters must be provided to connect to the database.

    Creates the database if it doesn't exist and ensures all tables
    are created with appropriate column types (including JSONB for
    JSON data storage).

    Args:
        uri: PostgreSQL connection string in libpq format
            (e.g., "dbname='zac' user='zabbix' host='localhost' password='secret'")
        db: Name of the database
        user: Username for authentication
        host: Database server hostname
        password: Password for authentication
        port: Port number (defaults to 5432)
        timeout: Connection timeout in seconds (optional)

    Returns:
        sa.Engine: Configured SQLAlchemy engine for the application database

    Example:
        ```python
        engine = init_db(
            uri=(
                "dbname='zac' user='zabbix' host='localhost' "
                "password='secret' port=5432 connect_timeout=2"
            )
        )
        # OR
        engine = init_db(
            db="zac",
            user="zabbix",
            host="localhost",
            password="secret",
            port=5432,
            timeout=2,
        )
        ```
    """
    # Parse the connection string into a structured format OR use individual parameters
    if uri:
        params = parse_postgres_uri(uri)
    elif db and user and host and password:
        params = PostgresConnectionParams(
            dbname=db,
            user=user,
            host=host,
            password=password,
            port=port,
            connect_timeout=timeout,
        )
    else:
        raise ValueError("Either uri or db, user, host, and password must be provided")

    # Create SQLAlchemy URL from parameters
    app_url = sa.URL.create(
        drivername="postgresql",
        database=params.dbname,
        username=params.user,
        password=params.password,
        host=params.host,
        port=params.port,
    )

    if not database_exists(app_url):
        create_database(app_url)

    # Include connect_timeout in engine options if specified
    engine_kwargs = {}
    if params.connect_timeout is not None:
        engine_kwargs["connect_args"] = {"connect_timeout": int(params.connect_timeout)}

    engine = sa.create_engine(app_url, **engine_kwargs)
    Base.metadata.create_all(engine)

    return engine
