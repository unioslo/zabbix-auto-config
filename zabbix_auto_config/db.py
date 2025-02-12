from __future__ import annotations

import logging
from typing import Optional

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.models import DBSettings
from zabbix_auto_config.models import Settings

logger = logging.getLogger(__name__)


def get_connection(
    settings: DBSettings, dbname: Optional[str] = None
) -> psycopg2.extensions.connection:
    """Get a connection to the Postgres database.

    Optionally specify a different database name to connect to."""
    kwargs = settings.get_connect_kwargs()
    if dbname:  # HACK: we need to connect to 'postgres' to create a new database
        kwargs["dbname"] = dbname
    return psycopg2.connect(**kwargs)


class PostgresDBInitializer:
    def __init__(self, config: Settings) -> None:
        self.config = config

    def init_db(self) -> None:
        """Initialize database and tables idempotently."""
        # Create the database if it doesn't exist
        if self.config.zac.db.init.db:
            self._init_db()

        # Create tables if they don't exist
        if self.config.zac.db.init.tables:
            self._init_tables()

    def _init_db(self) -> None:
        """Create the database if it doesn't exist."""
        # Cannot create a database inside a transaction block (no with statement)
        conn = get_connection(self.config.zac.db, dbname="postgres")
        try:
            # Required for CREATE DATABASE
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

            with conn.cursor() as cur:
                # Check if database exists
                cur.execute(
                    f"SELECT 1 FROM pg_database WHERE datname = '{self.config.zac.db.dbname}'"
                )
                exists = cur.fetchone()

                if not exists:
                    logger.info("Creating database %s", self.config.zac.db.dbname)
                    cur.execute(f"CREATE DATABASE {self.config.zac.db.dbname}")
        finally:
            conn.close()

    def _init_tables(self) -> None:
        with get_connection(self.config.zac.db) as conn:
            with conn.cursor() as cur:
                logger.info("Creating table %s", self.config.zac.db.tables.hosts)
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self.config.zac.db.tables.hosts} (
                        data jsonb
                    )
                """)

                logger.info("Creating table %s", self.config.zac.db.tables.hosts_source)
                cur.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self.config.zac.db.tables.hosts_source} (
                        data jsonb
                    )
                """)
                conn.commit()


def init_db(config: Settings) -> None:
    """Initialize Postgres database and tables idempotently.

    Creates the database and tables if they don't exist and the configuration
    specifies that they should be initialized.
    """
    initializer = PostgresDBInitializer(config)
    try:
        initializer.init_db()
    except psycopg2.Error as e:
        raise ZACException(f"Error initializing database: {e}") from e
