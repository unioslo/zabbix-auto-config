from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Optional

import psycopg2
import structlog
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.models import DBSettings
from zabbix_auto_config.models import Settings

logger = structlog.stdlib.get_logger(__name__)


def get_connection(
    settings: DBSettings, dbname: Optional[str] = None
) -> psycopg2.extensions.connection:
    """Get a connection to the Postgres database.

    Optionally specify a different database name to connect to."""
    kwargs = settings.get_connect_kwargs()
    if dbname:  # HACK: we need to connect to 'postgres' to create a new database
        kwargs["dbname"] = dbname
    return psycopg2.connect(**kwargs)


@contextmanager
def init_resource(
    resource: str, exc_type: type[Exception] = psycopg2.Error
) -> Generator[None, None, None]:
    """Initialize a resource, optionally guarding it from propagating exception."""
    try:
        yield
    except exc_type as e:
        logger.error("Failed to initialize DB resource", resource=resource, e=e)
        raise ZACException(f"Failed to initialize {resource}: {e}") from e


class PostgresDBInitializer:
    def __init__(self, config: Settings) -> None:
        self.config = config

    def init(self) -> None:
        """Initialize database and tables idempotently."""
        # Create the database if it doesn't exist
        if self.config.zac.db.init.db:
            with init_resource("database"):
                self._init_db()

        # Create tables if they don't exist
        if self.config.zac.db.init.tables:
            with init_resource("tables"):
                self._init_tables()

    def _zac_db_exists(self) -> bool:
        log = logger.bind(db=self.config.zac.db.dbname)
        try:
            with get_connection(self.config.zac.db):
                log.debug("ZAC database already exists")
        except psycopg2.Error as e:
            log.debug(
                "Failed to connect to database. Assuming it doesn't exist.",
                error=e,
            )
            return False
        return True

    def _init_db(self) -> None:
        """Create the database if it doesn't exist."""
        if self._zac_db_exists():
            return

        log = logger.bind(db=self.config.zac.db.dbname)

        # Cannot create a database inside a transaction block (no with statement)
        conn = get_connection(self.config.zac.db, dbname="postgres")
        try:
            # Required for CREATE DATABASE
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

            with conn.cursor() as cur:
                # Check if database exists
                cur.execute(
                    sql.SQL("SELECT 1 FROM pg_database WHERE datname = %s"),
                    [self.config.zac.db.dbname],
                )
                exists = cur.fetchone()

                if not exists:  # should exist given _zac_db_exists()
                    log.debug("Creating database")
                    cur.execute(
                        sql.SQL("CREATE DATABASE {}").format(
                            sql.Identifier(self.config.zac.db.dbname)
                        )
                    )
        finally:
            conn.close()

    def _init_tables(self) -> None:
        with get_connection(self.config.zac.db) as conn:
            log = logger.bind(db=self.config.zac.db.dbname)
            with conn.cursor() as cur:
                # Create hosts table
                log.debug(
                    "Creating table if it doesn't exist",
                    table=self.config.zac.db.tables.hosts,
                )
                cur.execute(
                    sql.SQL("""
                    CREATE TABLE IF NOT EXISTS {} (
                        data jsonb
                    )
                """).format(sql.Identifier(self.config.zac.db.tables.hosts))
                )

                # Create hosts_source table
                log.debug(
                    "Creating table if it doesn't exist",
                    table=self.config.zac.db.tables.hosts_source,
                )
                cur.execute(
                    sql.SQL("""
                    CREATE TABLE IF NOT EXISTS {} (
                        data jsonb
                    )
                """).format(sql.Identifier(self.config.zac.db.tables.hosts_source))
                )
                conn.commit()


def init_db(config: Settings) -> None:
    """Initialize Postgres database and tables idempotently.

    Creates the database and tables if they don't exist and the configuration
    specifies that they should be initialized.
    """
    initializer = PostgresDBInitializer(config)
    try:
        initializer.init()
    except psycopg2.Error as e:
        raise ZACException(f"Error initializing database: {e}") from e
