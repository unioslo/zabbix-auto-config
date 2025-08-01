from __future__ import annotations

import itertools
import logging
import multiprocessing
import multiprocessing.synchronize
import os
import os.path
import queue
import random
import re
import signal
import time
from collections import Counter
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from enum import Enum
from typing import TYPE_CHECKING
from typing import Any
from typing import Optional
from typing import TypeVar

import httpx
import psycopg2
import structlog
from psycopg2 import sql
from pydantic import ValidationError

from zabbix_auto_config import compat
from zabbix_auto_config import db
from zabbix_auto_config import models
from zabbix_auto_config import utils
from zabbix_auto_config._types import HostModifier
from zabbix_auto_config._types import SourceCollectorModule
from zabbix_auto_config._types import ZacTags
from zabbix_auto_config.errcount import RollingErrorCounter
from zabbix_auto_config.exceptions import SourceCollectorError
from zabbix_auto_config.exceptions import SourceCollectorTypeError
from zabbix_auto_config.exceptions import ZabbixAPIException
from zabbix_auto_config.exceptions import ZabbixAPISessionExpired
from zabbix_auto_config.exceptions import ZabbixNotFoundError
from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.failsafe import check_failsafe
from zabbix_auto_config.pyzabbix.client import ZabbixAPI
from zabbix_auto_config.pyzabbix.enums import InterfaceType
from zabbix_auto_config.pyzabbix.enums import InventoryMode
from zabbix_auto_config.pyzabbix.enums import MonitoringStatus
from zabbix_auto_config.pyzabbix.types import CreateHostInterfaceDetails
from zabbix_auto_config.pyzabbix.types import Host
from zabbix_auto_config.pyzabbix.types import HostGroup
from zabbix_auto_config.pyzabbix.types import HostInterface
from zabbix_auto_config.pyzabbix.types import Maintenance
from zabbix_auto_config.pyzabbix.types import ModelWithHosts
from zabbix_auto_config.pyzabbix.types import Proxy
from zabbix_auto_config.pyzabbix.types import Template
from zabbix_auto_config.pyzabbix.types import UpdateHostInterfaceDetails
from zabbix_auto_config.state import State

if TYPE_CHECKING:
    from psycopg2.extensions import cursor as Cursor


logger = structlog.stdlib.get_logger(__name__)


class BaseProcess(multiprocessing.Process):
    def __init__(self, name: str, state: State, config: models.Settings) -> None:
        super().__init__()
        self.name = name
        self.state = state
        self.config = config

        self.update_interval = 1
        self.next_update = datetime.now()

        self.state.set_ok()
        self.stop_event = multiprocessing.Event()

    def get_db_connection(self) -> psycopg2.extensions.connection:
        try:
            return db.get_connection(self.config.zac.db)
        except psycopg2.OperationalError as e:
            logger.error("Unable to connect to database.")
            raise ZACException(*e.args) from e

    def run(self) -> None:
        logger.debug("Process starting")

        with SignalHandler(self.stop_event):
            while not self.stop_event.is_set():
                parent_process = multiprocessing.parent_process()
                if parent_process is None or not parent_process.is_alive():
                    logger.error("Parent is dead. Stopping")
                    self.stop()
                    break

                if self.next_update > datetime.now():
                    time.sleep(1)
                    continue

                start_time = datetime.now()
                self.next_update = datetime.now() + timedelta(
                    seconds=self.update_interval
                )

                try:
                    self.work()
                except Exception as e:
                    log = logger.bind(error=e)
                    # These are the error types we handle ourselves then continue
                    if isinstance(e, httpx.TimeoutException):
                        log.error("Timeout exception")
                    elif isinstance(e, ZACException):
                        log.error("Work exception")
                    elif isinstance(e, ZabbixAPISessionExpired):
                        log.error("Zabbix API session expired")
                        if isinstance(self, ZabbixUpdater):
                            log.info("Reconnecting to Zabbix API and retrying update")
                            self.login()
                    elif isinstance(e, ZabbixAPIException):
                        log.error("Zabbix API exception")
                    else:
                        raise e  # all other exceptions are fatal
                    self.state.set_error(e)
                else:
                    self.state.set_ok()

                work_duration = datetime.now() - start_time
                self.state.record_execution(work_duration)

                # Only warn about long-running tasks if:
                # 1. Interval is non-zero (not continuous processing)
                # 2. Work took longer than the interval
                # 3. Haven't warned in last hour
                if (
                    self.update_interval > 0
                    and work_duration.total_seconds() > self.update_interval
                    and (
                        not self.state.last_duration_warning
                        or datetime.now() - self.state.last_duration_warning
                        > timedelta(hours=1)
                    )
                ):
                    logger.warning(
                        "Work duration exceeded update interval",
                        work_duration=utils.format_timedelta(work_duration),
                        update_interval=utils.format_timedelta(
                            timedelta(seconds=self.update_interval)
                        ),
                        average_duration=utils.format_timedelta(
                            self.state.avg_duration
                        ),
                        max_duration=utils.format_timedelta(self.state.max_duration),
                        updates=self.state.execution_count,
                    )
                    self.state.last_duration_warning = datetime.now()

        logger.info("Process exiting")

    def stop(self) -> None:
        """Stop the process by setting its stop event."""
        logger.info("Stopping process")
        self.stop_event.set()

    def work(self) -> None:
        pass


class SignalHandler:
    def __init__(self, event: multiprocessing.synchronize.Event) -> None:
        self.event = event
        self.old_sigint_handler = signal.getsignal(signal.SIGINT)
        self.old_sigterm_handler = signal.getsignal(signal.SIGTERM)

    def __enter__(self) -> None:
        # Set new signal handlers when entering the context
        # Calling signal.signal() assigns new handler and returns the old one
        self.old_sigint_handler = signal.signal(signal.SIGINT, self._handler)
        self.old_sigterm_handler = signal.signal(signal.SIGTERM, self._handler)

    def __exit__(self, *args: Any) -> None:
        signal.signal(signal.SIGINT, self.old_sigint_handler)
        signal.signal(signal.SIGTERM, self.old_sigterm_handler)

    def _handler(self, signum: int, frame: Any) -> None:
        logger.bind(signal_name=signal.Signals(signum).name).info("Received signal")
        self.event.set()


class SourceCollectorProcess(BaseProcess):
    def __init__(
        self,
        name: str,
        state: State,
        config: models.Settings,
        module: SourceCollectorModule,
        settings: models.SourceCollectorSettings,
        source_hosts_queue: multiprocessing.Queue[models.Host],
    ) -> None:
        super().__init__(name, state, config)
        self.module = module
        self.settings = settings

        self.source_hosts_queue = source_hosts_queue
        self.source_hosts_queue.cancel_join_thread()  # Don't wait for empty queue when exiting

        self.update_interval = self.settings.update_interval

        # All extra fields in the collector config are passed as kwargs to the collector
        self.collector_config = settings.extra_kwargs()

        # Repeated errors will disable the source
        self.disabled = False
        self.disabled_until = datetime.now()
        self.error_counter = RollingErrorCounter(
            duration=self.settings.error_duration,
            tolerance=self.settings.error_tolerance,
        )

    def work(self) -> None:
        # If we are disabled, we must check if we should be re-enabled.
        # If not, we raise a ZACException, so that the state of the process
        # is marked as not ok.
        if self.disabled:
            if self.disabled_until > datetime.now():
                time_left = self.disabled_until - datetime.now()
                raise ZACException(
                    f"Source is disabled for {utils.format_timedelta(time_left)}"
                )
            else:
                logger.info("Reactivating source")
                self.disabled = False

        logger.info("Collection starting")

        try:
            self.collect()
        except Exception as e:
            self.handle_error(e)
        else:
            self.handle_success()

    def increase_update_interval(self) -> None:
        """Increase the update interval by the backoff factor."""

        new_interval = self.update_interval * self.settings.backoff_factor
        if new_interval > self.settings.max_backoff:
            new_interval = self.settings.max_backoff
            logger.info(
                "Reached max backoff",
                max_backoff=self.settings.max_backoff,
            )
        old_interval = self.update_interval
        self.update_interval = new_interval
        logger.info(
            "Backing off, increasing update interval",
            update_interval=self.update_interval,
            old_interval=old_interval,
        )

    def reset_update_interval(self) -> None:
        """Reset the update interval to its original value."""
        if self.update_interval == self.settings.update_interval:
            return  # Nothing to do
        self.update_interval = self.settings.update_interval
        logger.info(
            "Reset update interval",
            update_interval=self.update_interval,
        )

    def handle_success(self) -> None:
        """Handle a successful collection."""
        self.reset_update_interval()

    def handle_error(self, e: Exception) -> None:
        """Handle exceptions raised during collection."""
        logger.error("Collect exception", error=str(e))
        self.error_counter.add(exception=e)

        strat_handlers = {
            models.FailureStrategy.BACKOFF: self.increase_update_interval,
            models.FailureStrategy.EXIT: self.stop,
            models.FailureStrategy.DISABLE: self.disable,
        }
        strat = self.settings.failure_strategy

        if handler := strat_handlers.get(strat):
            if (
                not strat.supports_error_tolerance()
                or self.error_counter.tolerance_exceeded()
            ):
                handler()
            else:
                logger.debug(
                    "Source has not reached error tolerance of. Keeping it enabled",
                    error_tolerance=self.settings.error_tolerance,
                    count=self.error_counter.count(),
                )
        else:
            logger.info(
                "Source has no failure handling strategy. Keeping it enabled",
            )

        raise ZACException(f"Failed to collect from source {self.name!r}: {e}") from e

    def disable(self) -> None:
        if self.disabled:
            logger.warning("Attempted to disable already disabled source. Ignoring")
            return

        self.disabled = True
        disable_duration = self.settings.disable_duration

        logger.info("Disabling source", disable_duration=disable_duration)
        self.disabled_until = datetime.now() + timedelta(seconds=disable_duration)
        # Reset the error counter so that previous errors don't count towards
        # the error counter in the next run in case the disable duration is short
        self.error_counter.reset()

    def collect(self) -> None:
        start_time = time.time()
        try:
            hosts = self.module.collect(**self.collector_config)
            assert isinstance(hosts, list), "Collect module did not return a list"
        except Exception as e:
            raise SourceCollectorError(e) from e

        valid_hosts: list[models.Host] = []
        for host in hosts:
            if self.stop_event.is_set():
                logger.debug("Told to stop. Breaking")
                break

            if not isinstance(host, models.Host):
                raise SourceCollectorTypeError(
                    f"Collected object is not a Host object: {host!r}. Type: {type(host)}"
                )

            host.sources = {self.name}
            valid_hosts.append(host)

        # Add source hosts to queue
        source_hosts = {
            "source": self.name,
            "hosts": valid_hosts,
        }
        if self.source_hosts_queue.full():
            logger.warning(
                "Collection outpacing processing. Consider extending the update interval."
            )
            utils.drain_queue(self.source_hosts_queue)
        self.source_hosts_queue.put_nowait(source_hosts)

        logger.info(
            "Done collecting hosts from source",
            count=len(valid_hosts),
            duration=time.time() - start_time,
            next_update=self.next_update.isoformat(timespec="seconds"),
        )


class HostAction(Enum):
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    NO_CHANGE = "no_change"
    NOT_FOUND = "not_found"


class SourceHandlerProcess(BaseProcess):
    def __init__(
        self,
        name: str,
        state: State,
        config: models.Settings,
        source_hosts_queues: list[multiprocessing.Queue[models.Host]],
    ) -> None:
        super().__init__(name, state, config)

        # NOTE: This interval should not be changed!
        # A low value here makes it possible to constantly poll the
        # source host queues for new hosts.
        self.update_interval = 1

        self.db_connection = self.get_db_connection()
        self.db_source_table = sql.Identifier(self.config.zac.db.tables.hosts_source)

        self.source_hosts_queues = source_hosts_queues
        for source_hosts_queue in self.source_hosts_queues:
            source_hosts_queue.cancel_join_thread()  # Don't wait for empty queue when exiting

    def work(self) -> None:
        # Collect from all queues
        for source_hosts_queue in self.source_hosts_queues:
            if self.stop_event.is_set():
                logger.debug("Told to stop. Breaking")
                break
            try:
                source_hosts = source_hosts_queue.get_nowait()
            except queue.Empty:
                continue

            source = source_hosts["source"]
            hosts = source_hosts["hosts"]

            logger.info(
                "Handling hosts from source",
                count=len(hosts),
                source=source,
                queue_size=source_hosts_queue.qsize(),
            )
            self.handle_source_hosts(source, hosts)

    def handle_source_host(
        self,
        cursor: Cursor,
        host: models.Host,
        current_host: Optional[models.Host],
        source: str,
    ) -> HostAction:
        # TODO: still some optimizations to be done here with regards to bulk insertions/updates
        if current_host:
            if current_host == host:
                return HostAction.NO_CHANGE
            else:
                cursor.execute(
                    sql.SQL(
                        "UPDATE {} SET data = %s WHERE data->>'hostname' = %s AND data->'sources' ? %s"
                    ).format(self.db_source_table),
                    [host.model_dump_json(), host.hostname, source],
                )
                return HostAction.UPDATE
        else:
            cursor.execute(
                sql.SQL("INSERT INTO {} (data) VALUES (%s)").format(
                    self.db_source_table
                ),
                [host.model_dump_json()],
            )
            return HostAction.INSERT

    def get_current_source_hosts(
        self, cursor: Cursor, source: str
    ) -> dict[str, models.Host]:
        hosts: dict[str, models.Host] = {}
        cursor.execute(
            sql.SQL("SELECT data FROM {} WHERE data->'sources' ? %s").format(
                self.db_source_table
            ),
            [source],
        )
        for result in cursor.fetchall():
            try:
                host = models.Host(**result[0])
            except ValidationError:
                # TODO: ensure this actually identifies the faulty host
                logger.exception("Invalid host in source hosts table", host=str(result))
            except Exception:
                logger.exception(
                    "Error when validating host from source hosts table",
                    host=str(result),
                )
            else:
                hosts[host.hostname] = host
        return hosts

    def handle_source_hosts(self, source: str, hosts: list[models.Host]) -> None:
        start_time = time.time()

        actions: Counter[HostAction] = Counter()

        source_hostnames = {host.hostname for host in hosts}
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                sql.SQL(
                    "SELECT DISTINCT data->>'hostname' FROM {} WHERE data->'sources' ? %s"
                ).format(self.db_source_table),
                [source],
            )
            current_hostnames = {t[0] for t in db_cursor.fetchall()}

        removed_hostnames = current_hostnames - source_hostnames
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            for removed_hostname in removed_hostnames:
                db_cursor.execute(
                    sql.SQL(
                        "DELETE FROM {} WHERE data->>'hostname' = %s AND data->'sources' ? %s",
                    ).format(self.db_source_table),
                    [removed_hostname, source],
                )
                actions[HostAction.DELETE] += 1

        with self.db_connection, self.db_connection.cursor() as db_cursor:
            current_hosts = self.get_current_source_hosts(db_cursor, source)
            for host in hosts:
                current_host = current_hosts.get(host.hostname)
                action = self.handle_source_host(db_cursor, host, current_host, source)
                actions[action] += 1

        logger.info(
            "Done handling hosts from source",
            source=source,
            duration=time.time() - start_time,
            no_change=actions[HostAction.NO_CHANGE],
            updated=actions[HostAction.UPDATE],
            inserted=actions[HostAction.INSERT],
            deleted=actions[HostAction.DELETE],
            next_update=self.next_update.isoformat(timespec="seconds"),
        )


HostInterfaceDetailsT = TypeVar(
    "HostInterfaceDetailsT", CreateHostInterfaceDetails, UpdateHostInterfaceDetails
)


class SourceMergerProcess(BaseProcess):
    def __init__(
        self,
        name: str,
        state: State,
        config: models.Settings,
        host_modifiers: list[HostModifier],
    ) -> None:
        super().__init__(name, state, config)

        self.db_source_table = sql.Identifier(self.config.zac.db.tables.hosts_source)
        self.db_hosts_table = sql.Identifier(self.config.zac.db.tables.hosts)
        self.host_modifiers = host_modifiers

        self.db_connection = self.get_db_connection()

        self.update_interval = 60

    def work(self) -> None:
        self.merge_sources()

    def merge_hosts(self, hosts: list[models.Host]) -> models.Host:
        """Merge a list of hosts from different sources into a single host."""
        # merge_sources() guarantees the list is not empty
        # however, that could change without this method being updated.
        # Do an assert here so it's easier to debug if that happens.
        assert len(hosts) > 0, "Cannot merge empty list of hosts"

        merged_host = hosts[0]
        for host in hosts[1:]:
            merged_host.merge(host)
        return merged_host

    def handle_host(
        self,
        cursor: Cursor,
        current_host: Optional[models.Host],
        source_hosts: list[models.Host],
    ) -> HostAction:
        """Merge host and apply host modifiers. Updates DB if changed

        If host already exists (signalled by `current_host` arg), the host is updated
        in the database if it has changed in the source(s) or a modifier has changed it.

        If the host does not exist, it is inserted into the database.

        Args:
            cursor: Database cursor
            current_host: Host from the database, if it exists
            source_hosts: All versions of the host from different sources
        """
        host = self.merge_hosts(source_hosts)

        for host_modifier in self.host_modifiers:
            try:
                modified_host = host_modifier.module.modify(host.model_copy(deep=True))
                assert isinstance(modified_host, models.Host), (
                    f"Modifier returned invalid type: {type(modified_host)}"
                )
                assert host.hostname == modified_host.hostname, (
                    f"Modifier changed the hostname, '{host.hostname}' -> '{modified_host.hostname}'"
                )
                # Re-validate the host after modification
                host = host.model_validate(modified_host)
            except AssertionError as e:
                logger.error(
                    "Host was modified to be invalid by modifier",
                    host=host.hostname,
                    host_modifier=host_modifier.name,
                    error=str(e),
                )
            except Exception as e:
                logger.error(
                    "Error when running modifier on host",
                    host=host.hostname,
                    host_modifier=host_modifier.name,
                    error=str(e),
                )
                # TODO: Do more?

        if current_host:
            if current_host == host:
                return HostAction.NO_CHANGE
            else:
                cursor.execute(
                    sql.SQL(
                        "UPDATE {} SET data = %s WHERE data->>'hostname' = %s"
                    ).format(self.db_hosts_table),
                    [host.model_dump_json(), host.hostname],
                )
                return HostAction.UPDATE
        else:
            cursor.execute(
                sql.SQL("INSERT INTO {} (data) VALUES (%s)").format(
                    self.db_hosts_table
                ),
                [host.model_dump_json()],
            )
            return HostAction.INSERT

    def get_source_hosts(self, cursor: Cursor) -> dict[str, list[models.Host]]:
        cursor.execute(sql.SQL("SELECT data FROM {}").format(self.db_source_table))
        source_hosts: defaultdict[str, list[models.Host]] = defaultdict(list)
        for host in cursor.fetchall():
            try:
                host_model = models.Host(**host[0])
            except ValidationError:
                # TODO: ensure this actually identifies the faulty host
                logger.exception("Invalid host in source hosts table", host=host)
            except Exception:
                logger.exception(
                    "Error when parsing host from source hosts table", host=host
                )
            else:
                source_hosts[host_model.hostname].append(host_model)
        return source_hosts

    def get_hosts(self, cursor: Cursor) -> dict[str, models.Host]:
        cursor.execute(sql.SQL("SELECT data FROM {}").format(self.db_hosts_table))
        hosts: dict[str, models.Host] = {}
        for host in cursor.fetchall():
            try:
                host_model = models.Host(**host[0])
            except ValidationError:
                # TODO: ensure this log actually identifies the faulty host
                logger.exception("Invalid host in hosts table", host=host)
            except Exception:
                logger.exception("Error when parsing host from hosts table", host=host)
            else:
                hosts[host_model.hostname] = host_model
        return hosts

    def merge_sources(self) -> None:
        start_time = time.time()
        logger.info("Merge starting")
        actions: Counter[HostAction] = Counter()

        with self.db_connection, self.db_connection.cursor() as db_cursor:
            # Get all hostnames from source hosts and current (merged) hosts
            db_cursor.execute(
                sql.SQL("SELECT data->>'hostname' FROM {}").format(
                    self.db_source_table,
                )
            )
            # deduplicate hostnames by converting to a set
            source_hostnames = {t[0] for t in db_cursor.fetchall()}

            # Fetch all current hosts from the merged hosts table
            # and lock them so other processes can't modify them
            db_cursor.execute(
                sql.SQL("SELECT data->>'hostname' FROM {} FOR UPDATE").format(
                    self.db_hosts_table
                )
            )
            current_hostnames = {t[0] for t in db_cursor.fetchall()}

            # Remove hosts that are no longer in the source hosts table
            removed_hostnames = current_hostnames - source_hostnames
            if removed_hostnames and not self.stop_event.is_set():
                # Construct and execute a single DELETE query with WHERE IN clause
                db_cursor.execute(
                    sql.SQL("DELETE FROM {} WHERE data->>'hostname' = ANY(%s)").format(
                        self.db_hosts_table
                    ),
                    [list(removed_hostnames)],
                )
                # Update the delete action count
                actions[HostAction.DELETE] += len(removed_hostnames)

            # Merge source hosts and insert/update hosts table
            source_hosts_map = self.get_source_hosts(db_cursor)
            hosts = self.get_hosts(db_cursor)
            for hostname in source_hostnames:
                # NOTE: Should we finish handling all hosts before stopping?
                if self.stop_event.is_set():
                    logger.debug("Told to stop. Breaking")
                    break

                source_hosts = source_hosts_map.get(hostname)
                if not source_hosts:
                    logger.warning(
                        "Host not found in source hosts table", host=hostname
                    )
                    continue

                host = hosts.get(hostname)
                host_action = self.handle_host(db_cursor, host, source_hosts)
                actions[host_action] += 1

        logger.info(
            "Done with merge of source hosts",
            duration=time.time() - start_time,
            no_change=actions[HostAction.NO_CHANGE],
            updated=actions[HostAction.UPDATE],
            inserted=actions[HostAction.INSERT],
            deleted=actions[HostAction.DELETE],
            next_update=self.next_update.isoformat(timespec="seconds"),
        )


class ZabbixUpdater(BaseProcess):
    def __init__(self, name: str, state: State, config: models.Settings) -> None:
        super().__init__(name, state, config)

        self.db_hosts_table = sql.Identifier(self.config.zac.db.tables.hosts)
        self.db_connection = self.get_db_connection()

        self.zabbix_config = config.zabbix

        self.update_interval = 60  # default. Overriden in subclasses

        self.property_template_map = utils.read_map_file(
            os.path.join(self.zabbix_config.map_dir, "property_template_map.txt")
        )
        self.property_hostgroup_map = utils.read_map_file(
            os.path.join(self.zabbix_config.map_dir, "property_hostgroup_map.txt")
        )
        self.siteadmin_hostgroup_map = utils.read_map_file(
            os.path.join(self.zabbix_config.map_dir, "siteadmin_hostgroup_map.txt")
        )

        pyzabbix_logger = logging.getLogger("pyzabbix")
        pyzabbix_logger.setLevel(logging.ERROR)

        self.api = ZabbixAPI(
            self.zabbix_config.url,
            timeout=self.zabbix_config.timeout,  # timeout for connect AND read
            read_only=self.zabbix_config.dryrun,  # prevent accidental changes
            verify_ssl=self.zabbix_config.verify_ssl,
        )

        self.login()
        self.zabbix_version = self.api.version
        logger.info("Connected to Zabbix API", version=str(self.zabbix_version))

    def login(self) -> None:
        log = logger.bind(
            url=self.zabbix_config.url,
            username=self.zabbix_config.username,
            password=self.zabbix_config.password,
        )
        try:
            self.api.login(self.zabbix_config.username, self.zabbix_config.password)
        except httpx.ConnectError as e:
            log.error("Error while connecting to Zabbix")
            raise ZACException(*e.args) from e
        except httpx.TimeoutException as e:
            log.error("Timed out while connecting to Zabbix API", error=str(e))
            raise ZACException(*e.args) from e
        except (ZabbixAPIException, httpx.HTTPError) as e:
            log.error("Unable to login to Zabbix API", error=str(e))
            raise ZACException(*e.args) from e

    def work(self) -> None:
        start_time = time.time()
        logger.info("Zabbix update starting")
        self.do_update()
        logger.info(
            "Done with zabbix update",
            duration=time.time() - start_time,
            next_update=self.next_update.isoformat(timespec="seconds"),
        )

    def do_update(self) -> None:
        pass

    def get_db_hosts(self) -> dict[str, models.Host]:
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                sql.SQL("SELECT data FROM {} WHERE data->>'enabled' = 'true'").format(
                    self.db_hosts_table
                )
            )
            db_hosts: dict[str, models.Host] = {}
            for res in db_cursor.fetchall():
                try:
                    host = models.Host(**res[0])
                except ValidationError:
                    # TODO: log invalid host then remove it from the database
                    logger.exception("Invalid host in hosts table", host=str(res))
                except Exception:
                    logger.exception(
                        "Failed to parse host from hosts table", host=str(res)
                    )
                else:
                    db_hosts[host.hostname] = host
            return db_hosts

    def create_hostgroup(self, hostgroup_name: str) -> Optional[str]:
        log = logger.bind(hostgroup_name=hostgroup_name)
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Creating hostgroup")
            return None

        log.debug("Creating hostgroup")
        try:
            groupid = self.api.create_hostgroup(hostgroup_name)
            log.info("Created host group", groupid=groupid)
            return groupid
        except ZabbixAPIException as e:
            log.error("Failed to create hostgroup", error=e)
            return None


class ZabbixGarbageCollector(ZabbixUpdater):
    """Cleans up disabled hosts from maintenances in Zabbix."""

    def __init__(self, name: str, state: State, config: models.Settings) -> None:
        super().__init__(name, state, config)

        self.update_interval = self.config.zac.process.garbage_collector.update_interval

    def filter_disabled_hosts(
        self, model: ModelWithHosts
    ) -> tuple[list[Host], list[Host]]:
        """Returns a tuple of (active_hosts, disabled_hosts) from a model."""
        keep: list[Host] = []
        remove: list[Host] = []
        for host in model.hosts:
            if host.status == MonitoringStatus.OFF:
                remove.append(host)
            else:
                keep.append(host)
        return keep, remove

    def get_maintenances(self, disabled_hosts: list[Host]) -> list[Maintenance]:
        """Fetch all maintenances with disabled hosts in Zabbix."""
        return self.api.get_maintenances(hosts=disabled_hosts, select_hosts=True)

    def remove_disabled_hosts_from_maintenance(self, maintenance: Maintenance) -> None:
        """Remove all disabled hosts from a maintenance."""
        hosts_keep, hosts_remove = self.filter_disabled_hosts(maintenance)

        log = logger.bind(maintenance=maintenance.name)
        if self.zabbix_config.dryrun:
            log.info(
                "DRYRUN: Removing disabled hosts from maintenance",
                hosts=hosts_remove,
            )
            return

        # No disabled hosts in maintenance (Should never happen)
        if len(hosts_keep) == len(maintenance.hosts):
            log.debug("No disabled hosts in maintenance")
        # No hosts left in maintenance
        elif not hosts_keep:
            if self.config.zac.process.garbage_collector.delete_empty_maintenance:
                self.delete_maintenance(maintenance)
            else:
                log.error(
                    "Maintenance would be empty after removing disabled hosts. It must be deleted manually."
                )
        else:
            self.api.update_maintenance(maintenance, hosts_keep)
            log.info(
                "Removed disabled hosts from maintenance",
                hosts=hosts_remove,
            )

    def delete_maintenance(self, maintenance: Maintenance) -> None:
        """Delete a maintenance in Zabbix."""
        log = logger.bind(maintenance=maintenance.name)
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Deleting maintenance")
            return
        self.api.delete_maintenance(maintenance)
        log.info("Deleted maintenance")

    def cleanup_maintenances(self, disabled_hosts: list[Host]) -> None:
        maintenances = self.api.get_maintenances(
            hosts=disabled_hosts, select_hosts=True
        )
        for maintenance in maintenances:
            self.remove_disabled_hosts_from_maintenance(maintenance)

    def do_update(self) -> None:
        if not self.config.zac.process.garbage_collector.enabled:
            logger.debug("Garbage collection is disabled")
            return
        # Get all disabled hosts
        disabled_hosts = self.api.get_hosts(status=MonitoringStatus.OFF)
        self.cleanup_maintenances(list(disabled_hosts))


class ZabbixHostUpdater(ZabbixUpdater):
    def __init__(self, name: str, state: State, config: models.Settings) -> None:
        super().__init__(name, state, config)

        self.update_interval = self.config.zac.process.host_updater.update_interval

        # Fetch required host groups on startup
        self.disabled_hostgroup = self.get_or_create_hostgroup(
            self.zabbix_config.hostgroup_disabled
        )
        self.enabled_hostgroup = self.get_or_create_hostgroup(
            self.zabbix_config.hostgroup_all
        )

    def get_or_create_hostgroup(self, hostgroup: str) -> HostGroup:
        """Fetch a host group, creating it if it doesn't exist."""
        try:
            return self.api.get_hostgroup(hostgroup)
        except ZabbixNotFoundError:
            self.create_hostgroup(hostgroup)

        # DRYRUN: return mock group instead of re-fetching
        if self.config.zabbix.dryrun:
            return HostGroup(groupid="0", name=hostgroup)
        else:
            return self.api.get_hostgroup(hostgroup)

    def get_maintenances(self, zabbix_host: Host) -> list[Maintenance]:
        try:
            maintenances = self.api.get_maintenances(
                hosts=[zabbix_host],
                select_hosts=True,
            )
        except ZabbixAPIException:
            logger.exception(
                "Failed to fetch maintenances for host",
                host=zabbix_host.host,
                hostid=zabbix_host.hostid,
            )
            maintenances = []
        return maintenances

    def do_remove_host_from_maintenance(
        self, zabbix_host: Host, maintenance: Maintenance
    ) -> None:
        log = logger.bind(host=zabbix_host.host, maintenance=maintenance.name)
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Removing host from maintenance")
            return

        # Determine new hosts list for maintenance
        new_hosts = [
            host for host in maintenance.hosts if host.hostid != zabbix_host.hostid
        ]

        if not new_hosts:
            # NOTE: ZabbixGarbageCollector cleans this up if enabled
            log.info("Maintenance would be empty if removing host. Skipping.")
            return

        try:
            self.api.update_maintenance(maintenance, hosts=new_hosts)
        except ZabbixAPIException:
            log.exception("Failed to remove host from maintenance")
        else:
            log.info("Removed host from maintenance")

    def remove_host_from_maintenances(self, zabbix_host: Host) -> None:
        maintenances = self.get_maintenances(zabbix_host)
        for maintenance in maintenances:
            self.do_remove_host_from_maintenance(zabbix_host, maintenance)

    def disable_host(self, zabbix_host: Host) -> None:
        # Host needs to be removed from all maintenances before it is disabled
        log = logger.bind(host=zabbix_host.host, hostid=zabbix_host.hostid)

        self.remove_host_from_maintenances(zabbix_host)
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Disabling host")
            return

        try:
            self.api.update_host(
                zabbix_host,
                status=MonitoringStatus.OFF,
                templates=[],
                groups=[self.disabled_hostgroup],
            )
        except ZabbixAPIException:
            log.exception("Error when disabling host")
        else:
            log.info("Disabled host")

    def enable_host(self, db_host: models.Host) -> None:
        # TODO: Set correct proxy when enabling
        log = logger.bind(host=db_host.hostname)
        hostname = db_host.hostname
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Enabling host")
            return

        try:
            hosts = list(self.api.get_hosts(hostname, search=False))

            if hosts:
                host = hosts[0]
                self.api.update_host(
                    host, status=MonitoringStatus.ON, groups=[self.enabled_hostgroup]
                )
                log.info("Enabled existing host", hostid=host.hostid)
            else:
                interface = HostInterface(
                    dns=hostname,
                    ip="",
                    useip=False,
                    type=1,
                    port="10050",
                    main=1,
                )
                hostid = self.api.create_host(
                    hostname, groups=[self.enabled_hostgroup], interfaces=[interface]
                )
                log.info("Enabled new host", hostid=hostid)
        except ZabbixAPIException:
            log.exception("Error when enabling/creating host")

    def clear_proxy(self, zabbix_host: Host) -> None:
        log = logger.bind(host=zabbix_host.host, hostid=zabbix_host.hostid)

        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Clearing proxy on host")
            return
        try:
            self.api.clear_host_proxy(zabbix_host)
        except ZabbixAPIException:
            log.exception("Error clearing proxy on host")
        else:
            log.info("Cleared proxy on host")

    def set_interface(
        self,
        zabbix_host: Host,
        interface: models.Interface,
        useip: bool,
        old_interface: Optional[HostInterface] = None,
    ) -> None:
        log = logger.bind(
            host=zabbix_host.host,
            hostid=zabbix_host.hostid,
            interface_type=interface.type,
        )
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Setting interface on host")
            return

        if useip:
            dns = None
            ip = interface.endpoint
        else:
            dns = interface.endpoint
            ip = None

        try:
            ifacetype = InterfaceType(interface.type)
        except ValueError:
            log.error("Invalid/unknown interface type")
            return

        # Update existing interface
        if old_interface:
            self.update_host_interface(
                zabbix_host,
                interface,
                old_interface,
                ifacetype,
                useip,
                dns,
                ip,
            )
        # Create new interface
        else:
            self.create_host_interface(
                zabbix_host,
                interface,
                ifacetype,
                useip,
                dns,
                ip,
            )

    def create_host_interface(
        self,
        zabbix_host: Host,
        interface: models.Interface,
        ifacetype: InterfaceType,
        useip: bool,
        dns: Optional[str],
        ip: Optional[str],
    ) -> None:
        details = self.validate_interface_details(
            CreateHostInterfaceDetails, interface, zabbix_host
        )
        self.api.create_host_interface(
            zabbix_host,
            main=True,
            port=interface.port,
            type=ifacetype,
            use_ip=useip,
            dns=dns,
            ip=ip,
            details=details,
        )
        logger.info(
            "Created new interface",
            host=zabbix_host.host,
            hostid=zabbix_host.hostid,
            interface_type=ifacetype.name,
            use_ip=useip,
            dns=dns,
            ip=ip,
            port=interface.port,
        )

    def update_host_interface(
        self,
        zabbix_host: Host,
        interface: models.Interface,
        old_interface: HostInterface,
        ifacetype: InterfaceType,
        useip: bool,
        dns: Optional[str],
        ip: Optional[str],
    ) -> None:
        details = self.validate_interface_details(
            UpdateHostInterfaceDetails, interface, zabbix_host
        )

        self.api.update_host_interface(
            old_interface,
            hostid=zabbix_host.hostid,
            main=True,
            port=interface.port,
            type=ifacetype,
            use_ip=useip,
            dns=dns,
            ip=ip,
            details=details,
        )
        logger.info(
            "Updated existing interface on host",
            host=zabbix_host.host,
            hostid=zabbix_host.hostid,
            interface_type=ifacetype.name,
            interface_id=old_interface.interfaceid,
            use_ip=useip,
            dns=dns,
            ip=ip,
        )

    def validate_interface_details(
        self, cls: type[HostInterfaceDetailsT], interface: models.Interface, host: Host
    ) -> Optional[HostInterfaceDetailsT]:
        """Validate interface details from a source host.

        Attempts to construct a model used to create or update a host interface
        from host interface details of a source host."""
        if not interface.details:
            return None  # nothing to validate
        try:
            return cls.model_validate(interface.details)
        except ValidationError:
            logger.error(
                "Invalid interface details",
                interface_details=interface.details,
                host=host.host,
            )
        return None

    def set_inventory_mode(
        self, zabbix_host: Host, inventory_mode: InventoryMode
    ) -> None:
        log = logger.bind(
            host=zabbix_host.host,
            hostid=zabbix_host.hostid,
            inventory_mode=inventory_mode.value,
        )
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Setting inventory_mode on host")
            return

        self.api.update_host(zabbix_host, inventory_mode=inventory_mode)
        log.info("Setting inventory_mode on host")

    def set_inventory(self, zabbix_host: Host, inventory: dict[str, str]) -> None:
        log = logger.bind(
            host=zabbix_host.host,
            hostid=zabbix_host.hostid,
            inventory=inventory,
        )
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Setting inventory on host")
            return
        # TODO: refactor. Move everything in to ZabbixAPI.update_host?
        self.api.update_host_inventory(zabbix_host, inventory)
        logger.info("Set inventory on host")

    def set_proxy(self, zabbix_host: Host, zabbix_proxy: Proxy) -> None:
        log = logger.bind(
            host=zabbix_host.host,
            hostid=zabbix_host.hostid,
            proxy=zabbix_proxy.name,
        )
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Setting proxy host")
            return
        try:
            self.api.update_host_proxy(zabbix_host, zabbix_proxy)
        except ZabbixAPIException as e:
            log.error("Failed to set proxy on host", error=str(e))
        else:
            log.info("Set proxy on host")

    def set_tags(self, zabbix_host: Host, tags: ZacTags) -> None:
        log = logger.bind(
            host=zabbix_host.host,
            hostid=zabbix_host.hostid,
            tags=tags,
        )
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Setting tags on host")
            return
        zabbix_tags = utils.zac_tags2zabbix_tags(tags)
        try:
            self.api.update_host(zabbix_host, tags=zabbix_tags)
        except ZabbixAPIException as e:
            log.error("Failed to set tags on host", error=str(e))
        else:
            log.info("Set tags on host")

    def do_update(self) -> None:
        db_hosts = self.get_db_hosts()

        zhosts = self.api.get_hosts(
            status=MonitoringStatus.ON,
            # flags:0 = non-discovered host
            flags=0,
            select_interfaces=True,
            select_inventory=True,
            select_templates=True,
            select_tags=True,
            select_groups=True,
        )
        zabbix_hosts = {host.host: host for host in zhosts}

        zproxies = self.api.get_proxies()
        zabbix_proxies = {proxy.name: proxy for proxy in zproxies}
        if not zabbix_proxies:
            logger.warning("No Zabbix proxies found.")

        zabbix_managed_hosts: list[Host] = []
        zabbix_manual_hosts: list[Host] = []

        for host in zabbix_hosts.values():
            if self.stop_event.is_set():
                logger.debug("Told to stop. Breaking")
                break
            hostgroup_names = [group.name for group in host.groups]
            if self.zabbix_config.hostgroup_manual in hostgroup_names:
                zabbix_manual_hosts.append(host)
            else:
                zabbix_managed_hosts.append(host)

        db_hostnames = set(db_hosts)
        zabbix_hostnames = set(zabbix_hosts)

        zabbix_managed_hostnames = {host.host for host in zabbix_managed_hosts}
        zabbix_manual_hostnames = {host.host for host in zabbix_manual_hosts}

        hostnames_to_remove = list(
            zabbix_managed_hostnames - db_hostnames - zabbix_manual_hostnames
        )
        hostnames_to_add = list(
            db_hostnames - zabbix_managed_hostnames - zabbix_manual_hostnames
        )
        hostnames_in_both = list(
            db_hostnames.intersection(zabbix_managed_hostnames)
            - zabbix_manual_hostnames
        )
        hostnames_in_manual_and_source = list(
            db_hostnames.intersection(zabbix_manual_hostnames)
        )

        logger.info(
            "Resulting hosts",
            to_add=hostnames_to_add,
            to_remove=hostnames_to_remove,
            manual_and_source=hostnames_in_manual_and_source,
            zabbix_count=len(zabbix_hostnames),
            db_count=len(db_hostnames),
        )

        # Check if we have too many hosts to add/remove
        check_failsafe(self.config, hostnames_to_add, hostnames_to_remove)

        for hostname in hostnames_to_remove:
            if self.stop_event.is_set():
                logger.debug("Told to stop. Breaking")
                break
            zabbix_host = zabbix_hosts[hostname]
            self.disable_host(zabbix_host)

        for hostname in hostnames_to_add:
            if self.stop_event.is_set():
                logger.debug("Told to stop. Breaking")
                break
            db_host = db_hosts[hostname]
            self.enable_host(db_host)

        for hostname in hostnames_in_both:
            if self.stop_event.is_set():
                logger.debug("Told to stop. Breaking")
                break

            db_host = db_hosts[hostname]
            zabbix_host = zabbix_hosts[hostname]

            log = logger.bind(host=zabbix_host.host, hostid=zabbix_host.hostid)

            # Check proxy. A host with proxy_pattern should get a proxy that matches the pattern.
            zabbix_proxy_id = zabbix_host.proxyid
            zabbix_proxy = [
                proxy
                for proxy in zabbix_proxies.values()
                if proxy.proxyid == zabbix_proxy_id
            ]
            current_zabbix_proxy = zabbix_proxy[0] if zabbix_proxy else None
            if db_host.proxy_pattern:
                possible_proxies = [
                    proxy
                    for proxy in zabbix_proxies.values()
                    if re.match(db_host.proxy_pattern, proxy.name)
                ]
                if not possible_proxies:
                    log.error(
                        "Proxy pattern doesn't match any proxies.",
                        proxy_pattern=db_host.proxy_pattern,
                    )
                else:
                    new_proxy = random.choice(possible_proxies)
                    if current_zabbix_proxy and not re.match(
                        db_host.proxy_pattern,
                        current_zabbix_proxy.name,
                    ):
                        # Wrong proxy, set new
                        self.set_proxy(zabbix_host, new_proxy)
                    elif not current_zabbix_proxy:
                        # Missing proxy, set new
                        self.set_proxy(zabbix_host, new_proxy)
            elif not db_host.proxy_pattern and current_zabbix_proxy:
                # Should not have proxy, remove
                self.clear_proxy(zabbix_host)

            # Check the main/default interfaces
            if db_host.interfaces:
                zabbix_interfaces = zabbix_host.interfaces

                # Create dict of main interfaces only
                zabbix_interfaces = {
                    i.type: i for i in zabbix_host.interfaces if i.main == 1
                }

                for interface in db_host.interfaces:
                    log_if = log.bind(
                        interface_type=interface.type,
                        interface_endpoint=interface.endpoint,
                    )
                    # We assume that we're using an IP if the endpoint is a valid IP
                    useip = utils.is_valid_ip(interface.endpoint)
                    if zabbix_interface := zabbix_interfaces.get(interface.type):
                        if useip and (
                            zabbix_interface.ip != interface.endpoint
                            or zabbix_interface.port != interface.port
                            or zabbix_interface.useip != useip
                        ):
                            # This IP interface is configured wrong, set it
                            self.set_interface(
                                zabbix_host,
                                interface,
                                useip,
                                zabbix_interface,
                            )
                        elif not useip and (
                            zabbix_interface.dns != interface.endpoint
                            or zabbix_interface.port != interface.port
                            or zabbix_interface.useip != useip
                        ):
                            log_if.info("DNS interface is configured incorrectly")
                            # This DNS interface is configured wrong, set it
                            self.set_interface(
                                zabbix_host,
                                interface,
                                useip,
                                zabbix_interface,
                            )
                        if interface.type == 2 and interface.details:
                            details_dict = zabbix_interface.details
                            # Check that the interface details are correct.
                            # Note that the Zabbix API response may include more
                            # information than our back-end; ignore such keys.
                            if not all(
                                str(details_dict.get(k)) == str(v)
                                for k, v in interface.details.items()
                            ):
                                log_if.info("SNMP interface is configured incorrectly")
                                # This SNMP interface is configured wrong, set it.
                                self.set_interface(
                                    zabbix_host,
                                    interface,
                                    useip,
                                    zabbix_interface,
                                )
                    else:
                        # This interface is missing, set it
                        self.set_interface(zabbix_host, interface, useip, None)

            # Check current tags and apply db tags
            other_zabbix_tags = utils.zabbix_tags2zac_tags(
                [
                    tag
                    for tag in zabbix_host.tags
                    if not tag.tag.startswith(self.zabbix_config.tags_prefix)
                ]
            )  # These are tags outside our namespace/prefix. Keep them.
            current_tags = utils.zabbix_tags2zac_tags(
                [
                    tag
                    for tag in zabbix_host.tags
                    if tag.tag.startswith(self.zabbix_config.tags_prefix)
                ]
            )
            db_tags = db_host.tags
            ignored_tags = set(
                filter(
                    lambda tag: not tag[0].startswith(self.zabbix_config.tags_prefix),
                    db_tags,
                )
            )
            if ignored_tags:
                db_tags = db_tags - ignored_tags
                log.warning(
                    "Ignoring tags not matching configured tag prefix",
                    tags=ignored_tags,
                    tag_prefix=self.zabbix_config.tags_prefix,
                )

            tags_to_remove = current_tags - db_tags
            tags_to_add = db_tags - current_tags
            tags = db_tags.union(other_zabbix_tags)
            if tags_to_remove or tags_to_add:
                if tags_to_remove:
                    log.debug("Going to remove tags", tags=tags_to_remove)
                if tags_to_add:
                    log.debug("Going to add tags", tags=tags_to_add)
                self.set_tags(zabbix_host, tags)

            if zabbix_host.inventory_mode != InventoryMode.AUTOMATIC:
                self.set_inventory_mode(zabbix_host, InventoryMode.AUTOMATIC)

            if db_host.inventory:
                if zabbix_host.inventory:
                    changed_inventory = {
                        k: v
                        for k, v in db_host.inventory.items()
                        if db_host.inventory[k] != zabbix_host.inventory.get(k, None)
                    }
                else:
                    changed_inventory = db_host.inventory

                if changed_inventory:
                    # inventory outside of zac management
                    ignored_inventory = {
                        k: v
                        for k, v in changed_inventory.items()
                        if k not in self.zabbix_config.managed_inventory
                    }

                    # inventories managed by zac and to be updated
                    inventory = {
                        k: v
                        for k, v in changed_inventory.items()
                        if k in self.zabbix_config.managed_inventory
                    }
                    if inventory:
                        self.set_inventory(zabbix_host, inventory)
                    if ignored_inventory:
                        log.warning(
                            "Zac is not configured to manage inventory properties",
                            ignored_inventory=ignored_inventory,
                        )


class ZabbixTemplateUpdater(ZabbixUpdater):
    def __init__(self, name: str, state: State, config: models.Settings) -> None:
        super().__init__(name, state, config)
        self.update_interval = self.config.zac.process.template_updater.update_interval

    def clear_templates(self, templates: list[Template], host: Host) -> None:
        log = logger.bind(
            host=host.host,
            hostid=host.hostid,
            templates=[t.host for t in templates],
        )
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Clearing templates on host")
            return

        try:
            self.api.unlink_templates_from_hosts(templates, [host], clear=True)
        except ZabbixAPIException as e:
            log.error("Error when clearing templates on host", error=str(e))
        else:
            log.info("Cleared templates on host")

    def set_templates(self, templates: list[Template], host: Host) -> None:
        # For logging
        log = logger.bind(
            host=host.host,
            hostid=host.hostid,
            templates=[t.host for t in templates],
        )

        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Setting templates on host")
            return

        try:
            self.api.link_templates_to_hosts(templates, [host])
        except ZabbixAPIException as e:
            log.error("Error setting templates on host", error=str(e))
        else:
            log.info("Set templates on host")

    def do_update(self) -> None:
        # Determine names of templates we are managing
        managed_template_names = set(
            itertools.chain.from_iterable(self.property_template_map.values())
        )
        zabbix_templates: dict[str, Template] = {}
        for zabbix_template in self.api.get_templates():
            zabbix_templates[zabbix_template.host] = zabbix_template

        managed_template_names = managed_template_names.intersection(
            set(zabbix_templates)
        )  # If the template isn't in zabbix we can't manage it

        # Get hosts from DB
        db_hosts = self.get_db_hosts()

        # Get hosts from Zabbix
        zabbix_hosts = self.api.get_hosts(
            status=MonitoringStatus.ON,
            flags=0,
            select_groups=True,
            select_templates=True,
        )

        for zabbix_host in zabbix_hosts:
            log = logger.bind(
                host=zabbix_host.host,
                hostid=zabbix_host.hostid,
                groups=[group.name for group in zabbix_host.groups],
            )
            if self.stop_event.is_set():
                log.debug("Told to stop. Breaking")
                break

            # Manually managed host - skip it
            if self.zabbix_config.hostgroup_manual in [
                group.name for group in zabbix_host.groups
            ]:
                log.debug("Skipping manual host")
                continue

            # Disabled hosts are not managed
            if not (db_host := db_hosts.get(zabbix_host.host)):
                log.debug("Skipping host (It is not enabled in the database)")
                continue

            # Determine managed templates
            synced_template_names: set[str] = set()
            for prop in db_host.properties:
                if template_names := self.property_template_map.get(prop):
                    synced_template_names.update(template_names)
            synced_template_names = synced_template_names.intersection(
                set(zabbix_templates)  # list of dict keys
            )  # If the template isn't in zabbix we can't manage it

            host_templates: dict[str, Template] = {}
            for zabbix_template in zabbix_host.parent_templates:
                host_templates[zabbix_template.host] = zabbix_template

            old_host_templates = host_templates.copy()
            host_templates_to_remove: dict[str, Template] = {}

            # Update templates on host
            for template_name in list(host_templates):
                if (
                    template_name in managed_template_names
                    and template_name not in synced_template_names
                ):
                    log.debug(
                        "Going to remove template from host.", template=template_name
                    )
                    host_templates_to_remove[template_name] = host_templates[
                        template_name
                    ]
                    del host_templates[template_name]
            for template_name in synced_template_names:
                if template_name not in host_templates:
                    log.debug("Going to add template to host.", template=template_name)
                    host_templates[template_name] = zabbix_templates[template_name]
            if host_templates != old_host_templates:
                log.info(
                    "Updating templates on host",
                    old_templates=list(old_host_templates.keys()),
                    new_templates=list(host_templates.keys()),
                )
                if host_templates_to_remove:
                    self.clear_templates(
                        list(host_templates_to_remove.values()), zabbix_host
                    )
                # TODO: Setting templates might not be necessary if we only removed templates. Consider refactor
                # TODO: Setting templates should not be performed if template clearing has failed (will lead to unlink without clear)
                self.set_templates(list(host_templates.values()), zabbix_host)


class ZabbixHostgroupUpdater(ZabbixUpdater):
    def __init__(self, name: str, state: State, config: models.Settings) -> None:
        super().__init__(name, state, config)
        self.update_interval = self.config.zac.process.hostgroup_updater.update_interval

    def set_hostgroups(self, host: Host, hostgroups: list[HostGroup]) -> None:
        """Set host groups on a host given a list of host groups."""
        log = logger.bind(
            host=host.host,
            hostid=host.hostid,
            hostgroups=[hg.name for hg in hostgroups],
        )
        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Setting hostgroups on host")
            return
        try:
            self.api.set_host_hostgroups(host, hostgroups)
        except ZabbixAPIException as e:
            log.error("Error when setting hostgroups on host", error=str(e))
        else:
            log.info("Set hostgroups on host")

    def create_extra_hostgroups(self, existing_hostgroups: list[HostGroup]) -> None:
        """Creates additonal host groups based on the prefixes specified
        in the config file. These host groups are not assigned hosts by ZAC."""
        hostgroup_names = {h.name for h in existing_hostgroups}

        for prefix in self.zabbix_config.extra_siteadmin_hostgroup_prefixes:
            mapping = utils.mapping_values_with_prefix(
                self.siteadmin_hostgroup_map,  # this is copied in the function
                prefix=prefix,
                separator=self.zabbix_config.prefix_separator,
            )
            for hostgroups in mapping.values():
                for hostgroup in hostgroups:
                    if hostgroup in hostgroup_names:
                        continue
                    self.create_hostgroup(hostgroup)

    def create_templategroup(self, templategroup_name: str) -> Optional[str]:
        log = logger.bind(templategroup=templategroup_name)

        if self.zabbix_config.dryrun:
            log.info("DRYRUN: Creating template group")
            return None

        log.debug("Creating template group")
        try:
            groupid = self.api.create_templategroup(templategroup_name)
            log.info("Created template group", groupid=groupid)
            return groupid
        except ZabbixAPIException as e:
            log.error("Error when creating template group", error=str(e))
            return None

    def create_templategroups(self, existing_hostgroups: list[HostGroup]) -> None:
        """Creates template groups for each host group in the siteadmin
        mapping file with the configured template group prefix.

        For Zabbix <6.2, host groups are created instead of template groups."""
        # Construct a set of all template group names from siteadmin mapping file
        # by replacing the host group prefix with the template group prefix.
        # The prefix is determined by the separator defined in the config file.
        # If we use the template group prefix `Templates-`, we go from
        # `Siteadmin-bob-hosts` to `Templates-bob-hosts`.
        tgroups = {
            utils.with_prefix(
                tg,
                self.zabbix_config.templategroup_prefix,
                separator=self.zabbix_config.prefix_separator,
            )
            for tg in itertools.chain.from_iterable(
                self.siteadmin_hostgroup_map.values()
            )
        }
        if compat.templategroups_supported(self.zabbix_version):
            logger.debug(
                "Zabbix version supports template groups. Will create template groups.",
                version=str(self.zabbix_version),
            )
            self._create_templategroups(tgroups)
        else:
            logger.debug(
                "Zabbix version does not support template groups. Will create host groups instead of template groups.",
                version=str(self.zabbix_version),
            )
            self._create_templategroups_pre_62_compat(tgroups, existing_hostgroups)

    def _create_templategroups(self, tgroups: set[str]) -> None:
        """Create the given template groups if they don't exist.

        Args:
            tgroups: A set of template group names to create.
        """
        res = self.api.get_templategroups()
        existing_tgroups = {tg.name for tg in res}
        for tgroup in tgroups:
            if tgroup in existing_tgroups:
                continue
            self.create_templategroup(tgroup)

    def _create_templategroups_pre_62_compat(
        self, tgroups: set[str], existing_hostgroups: list[HostGroup]
    ) -> None:
        """Compatibility method for creating template groups on Zabbix <6.2.

        Because template groups do not exist in <6.2, we instead create
        host groups with the given names.

        Args:
            tgroups: A set of host group names to create.
        """
        existing_hgroup_names = {h.name for h in existing_hostgroups}
        for tgroup in tgroups:
            if tgroup in existing_hgroup_names:
                continue
            self.create_hostgroup(tgroup)

    def do_update(self) -> None:
        managed_hostgroup_names: set[str] = set(
            itertools.chain.from_iterable(self.property_hostgroup_map.values())
        )
        managed_hostgroup_names.update(
            itertools.chain.from_iterable(self.siteadmin_hostgroup_map.values())
        )

        existing_hostgroups = self.api.get_hostgroups()

        # Create extra host groups if necessary
        if self.zabbix_config.extra_siteadmin_hostgroup_prefixes:
            self.create_extra_hostgroups(existing_hostgroups)

        # Create template groups if enabled
        if self.zabbix_config.create_templategroups:
            self.create_templategroups(existing_hostgroups)

        zabbix_hostgroups: dict[str, HostGroup] = {}
        for zabbix_hostgroup in existing_hostgroups:
            zabbix_hostgroups[zabbix_hostgroup.name] = zabbix_hostgroup
            if zabbix_hostgroup.name.startswith(
                self.zabbix_config.hostgroup_source_prefix
            ):
                managed_hostgroup_names.add(zabbix_hostgroup.name)
            if zabbix_hostgroup.name.startswith(
                self.zabbix_config.hostgroup_importance_prefix
            ):
                managed_hostgroup_names.add(zabbix_hostgroup.name)
        managed_hostgroup_names.update([self.zabbix_config.hostgroup_all])

        # Get hosts from DB
        db_hosts = self.get_db_hosts()

        # Get hosts from Zabbix
        zabbix_hosts = self.api.get_hosts(
            status=MonitoringStatus.ON,
            flags=0,
            select_groups=True,
            select_templates=True,
        )
        # Iterate over hosts in Zabbix and update synced hosts
        for zabbix_host in zabbix_hosts:
            log = logger.bind(host=zabbix_host.host, hostid=zabbix_host.hostid)
            if self.stop_event.is_set():
                logger.debug("Told to stop. Breaking")
                break

            # Host is manually managed - skip it
            if self.zabbix_config.hostgroup_manual in [
                group.name for group in zabbix_host.groups
            ]:
                log.debug("Skipping manual host")
                continue

            # Disabled hosts are not managed
            if zabbix_host.host not in db_hosts:
                log.debug("Skipping host (It is not enabled in the database)")
                continue

            db_host = db_hosts[zabbix_host.host]

            # Determine host groups to sync for host
            # Sync host groups derived from its properties, siteadmins, sources, etc.
            synced_hostgroup_names = {self.zabbix_config.hostgroup_all}
            for prop in db_host.properties:
                if prop in self.property_hostgroup_map:
                    synced_hostgroup_names.update(self.property_hostgroup_map[prop])
            for siteadmin in db_host.siteadmins:
                if siteadmin in self.siteadmin_hostgroup_map:
                    synced_hostgroup_names.update(
                        self.siteadmin_hostgroup_map[siteadmin]
                    )
            for source in db_host.sources:
                synced_hostgroup_names.add(
                    f"{self.zabbix_config.hostgroup_source_prefix}{source}"
                )
            if db_host.importance is not None:
                synced_hostgroup_names.add(
                    f"{self.zabbix_config.hostgroup_importance_prefix}{db_host.importance}"
                )
            else:
                synced_hostgroup_names.add(
                    f"{self.zabbix_config.hostgroup_importance_prefix}X"
                )

            host_hostgroups: dict[str, HostGroup] = {}
            for zabbix_hostgroup in zabbix_host.groups:
                host_hostgroups[zabbix_hostgroup.name] = zabbix_hostgroup
            old_host_hostgroups = host_hostgroups.copy()

            for hostgroup_name in list(host_hostgroups):
                # TODO: Here lies a bug due to managed_hostgroup_names not being properly updated above?
                # NOTE (pederhan): Not sure what this refers to?
                if (
                    hostgroup_name in managed_hostgroup_names
                    and hostgroup_name not in synced_hostgroup_names
                ):
                    log.debug(
                        "Going to remove hostgroup from host", hostgroup=hostgroup_name
                    )
                    del host_hostgroups[hostgroup_name]

            # Update host groups for host
            # Creates synced host groups if they don't exist
            for hostgroup_name in synced_hostgroup_names:
                if hostgroup_name not in host_hostgroups.keys():
                    log.debug(
                        "Going to add hostgroup to host", hostgroup=hostgroup_name
                    )
                    zabbix_hostgroup = zabbix_hostgroups.get(hostgroup_name, None)
                    if not zabbix_hostgroup:
                        # The hostgroup doesn't exist. We need to create it.
                        hostgroup_id = self.create_hostgroup(hostgroup_name)
                        # Add group to mapping so we don't try to create it again
                        if hostgroup_id:
                            zabbix_hostgroup = self.api.get_hostgroup(hostgroup_id)
                            zabbix_hostgroups[hostgroup_name] = zabbix_hostgroup

                    if zabbix_hostgroup:
                        host_hostgroups[hostgroup_name] = zabbix_hostgroup

            # Compare names of host groups to see if they are changed
            if sorted(host_hostgroups) != sorted(old_host_hostgroups):
                log.info(
                    "Updating host groups on host",
                    old_hostgroups=old_host_hostgroups,
                    new_hostgroups=host_hostgroups,
                )
                self.set_hostgroups(zabbix_host, list(host_hostgroups.values()))
