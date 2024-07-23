from __future__ import annotations

import datetime
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
import sys
import time
from collections import Counter
from collections import defaultdict
from enum import Enum
from typing import TYPE_CHECKING
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import httpx
import psycopg2
from packaging.version import Version
from pydantic import ValidationError

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
from zabbix_auto_config.pyzabbix.types import Trigger
from zabbix_auto_config.pyzabbix.types import UpdateHostInterfaceDetails

from . import compat
from . import models
from . import utils
from ._types import HostModifier
from ._types import SourceCollectorModule
from ._types import ZacTags
from .errcount import RollingErrorCounter
from .exceptions import SourceCollectorError
from .exceptions import SourceCollectorTypeError
from .exceptions import ZabbixAPIException
from .exceptions import ZabbixNotFoundError
from .exceptions import ZACException
from .failsafe import check_failsafe
from .state import State

if TYPE_CHECKING:
    from psycopg2.extensions import cursor as Cursor


class BaseProcess(multiprocessing.Process):
    def __init__(self, name: str, state: State) -> None:
        super().__init__()
        self.name = name
        self.state = state

        self.update_interval = 1
        self.next_update = datetime.datetime.now()

        self.state.set_ok()
        self.stop_event = multiprocessing.Event()

    def run(self) -> None:
        logging.info("Process starting")

        with SignalHandler(self.stop_event):
            while not self.stop_event.is_set():
                parent_process = multiprocessing.parent_process()
                if parent_process is None or not parent_process.is_alive():
                    logging.error("Parent is dead. Stopping")
                    self.stop_event.set()
                    break

                if self.next_update > datetime.datetime.now():
                    # logging.debug(f"Waiting for next update {self.next_update.isoformat()}")
                    time.sleep(1)
                    continue

                self.next_update = datetime.datetime.now() + datetime.timedelta(
                    seconds=self.update_interval
                )

                try:
                    self.work()
                    self.state.set_ok()
                except Exception as e:
                    # These are the error types we handle ourselves then continue
                    if isinstance(e, httpx.TimeoutException):
                        logging.error("Timeout exception: %s", str(e))
                    elif isinstance(e, ZACException):
                        logging.error("Work exception: %s", str(e))
                    elif isinstance(e, ZabbixAPIException):
                        logging.error("API exception: %s", str(e))
                    else:
                        raise e  # all other exceptions are fatal
                    self.state.set_error(e)

                if (
                    self.update_interval > 1
                    and self.next_update < datetime.datetime.now()
                ):
                    # Only log warning when update_interval is actually changed from default
                    logging.warning(
                        "Next update is in the past. Interval too short? Lagging behind? Next update was: %s",
                        self.next_update.isoformat(timespec="seconds"),
                    )

        logging.info("Process exiting")

    def work(self) -> None:
        pass


class SignalHandler:
    def __init__(self, event: multiprocessing.synchronize.Event) -> None:
        self.event = event

    def __enter__(self) -> None:
        self.old_sigint_handler = signal.signal(signal.SIGINT, self._handler)
        self.old_sigterm_handler = signal.signal(signal.SIGTERM, self._handler)

    def __exit__(self, *args: Any) -> None:
        signal.signal(signal.SIGINT, self.old_sigint_handler)
        signal.signal(signal.SIGTERM, self.old_sigterm_handler)

    def _handler(self, signum: int, frame: Any) -> None:
        logging.info("Received signal: %s", signal.Signals(signum).name)
        self.event.set()


class SourceCollectorProcess(BaseProcess):
    def __init__(
        self,
        name: str,
        state: State,
        module: SourceCollectorModule,
        config: models.SourceCollectorSettings,
        source_hosts_queue: multiprocessing.Queue,
    ) -> None:
        super().__init__(name, state)
        self.module = module
        self.config = config

        self.source_hosts_queue = source_hosts_queue
        self.source_hosts_queue.cancel_join_thread()  # Don't wait for empty queue when exiting

        self.update_interval = self.config.update_interval

        # Pop off the config fields from the config we pass to the module
        # Leaves only the custom options defined for the collector in the config
        self.collector_config = config.model_dump()
        for key in self.config.model_fields:
            self.collector_config.pop(key, None)

        # Repeated errors will disable the source
        self.disabled = False
        self.disabled_until = datetime.datetime.now()
        self.error_counter = RollingErrorCounter(
            duration=self.config.error_duration,
            tolerance=self.config.error_tolerance,
        )

    def work(self) -> None:
        # If we are disabled, we must check if we should be re-enabled.
        # If not, we raise a ZACException, so that the state of the process
        # is marked as not ok.
        if self.disabled:
            if self.disabled_until > datetime.datetime.now():
                time_left = self.disabled_until - datetime.datetime.now()
                raise ZACException(
                    f"Source is disabled for {utils.timedelta_to_str(time_left)}"
                )
            else:
                logging.info("Reactivating source")
                self.disabled = False

        logging.info("Collection starting")

        try:
            self.collect()
        except Exception as e:
            logging.error("Collect exception: %s", str(e))
            self.error_counter.add(exception=e)
            if self.error_counter.tolerance_exceeded():
                if self.config.exit_on_error:
                    logging.critical(
                        "Error tolerance exceeded. Terminating application."
                    )
                    self.stop_event.set()
                    # TODO: raise exception with message above or just an empty exception?
                else:
                    self.disable()
            raise ZACException(
                f"Failed to collect from source {self.name!r}: {e}"
            ) from e

    def disable(self) -> None:
        if self.disabled:
            logging.warning("Attempted to disable already disabled source. Ignoring")
            return

        self.disabled = True
        disable_duration = self.config.disable_duration
        if disable_duration > 0:
            logging.info(
                "Disabling source '%s' for %s seconds", self.name, disable_duration
            )
            self.disabled_until = datetime.datetime.now() + datetime.timedelta(
                seconds=disable_duration
            )
        else:
            logging.info("Disabling source '%s' indefinitely", self.name)
            self.disabled_until = datetime.datetime.max

        # Reset the error counter so that previous errors don't count towards
        # the error counter in the next run in case the disable duration is short
        self.error_counter.reset()
        # TODO: raise specific exception here instead of ZACException

    def collect(self) -> None:
        start_time = time.time()
        try:
            hosts = self.module.collect(**self.collector_config)
            assert isinstance(hosts, list), "Collect module did not return a list"
        except Exception as e:
            raise SourceCollectorError(e) from e

        valid_hosts = []  # type: List[models.Host]
        for host in hosts:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            if not isinstance(host, models.Host):
                raise SourceCollectorTypeError(
                    f"Collected object is not a Host object: {host!r}. Type: {type(host)}"
                )

            host.sources = set([self.name])
            valid_hosts.append(host)

        # Add source hosts to queue
        source_hosts = {
            "source": self.name,
            "hosts": valid_hosts,
        }
        if self.source_hosts_queue.full():
            logging.warning(
                "Collection outpacing processing. Consider extending the update interval."
            )
            utils.drain_queue(self.source_hosts_queue)
        self.source_hosts_queue.put_nowait(source_hosts)

        logging.info(
            "Done collecting %d hosts from source, '%s', in %.2f seconds. Next update: %s",
            len(valid_hosts),
            self.name,
            time.time() - start_time,
            self.next_update.isoformat(timespec="seconds"),
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
        db_uri: str,
        source_hosts_queues: List[multiprocessing.Queue],
    ) -> None:
        super().__init__(name, state)

        self.db_uri = db_uri
        self.db_source_table = "hosts_source"

        try:
            self.db_connection = psycopg2.connect(self.db_uri)
            # TODO: Test connection? Cursor?
        except psycopg2.OperationalError as e:
            logging.error("Unable to connect to database.")
            raise ZACException(*e.args)

        self.source_hosts_queues = source_hosts_queues
        for source_hosts_queue in self.source_hosts_queues:
            source_hosts_queue.cancel_join_thread()  # Don't wait for empty queue when exiting

    def work(self) -> None:
        # Collect from all queues
        for source_hosts_queue in self.source_hosts_queues:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            try:
                source_hosts = source_hosts_queue.get_nowait()
            except queue.Empty:
                continue

            source = source_hosts["source"]
            hosts = source_hosts["hosts"]

            logging.debug(
                "Handling %d hosts from source, '%s', from queue. Current queue size: %d",
                len(source_hosts["hosts"]),
                source,
                source_hosts_queue.qsize(),
            )
            self.handle_source_hosts(source, hosts)

    def handle_source_host(
        self,
        cursor: "Cursor",
        host: models.Host,
        current_host: Optional[models.Host],
        source: str,
    ) -> HostAction:
        # TODO: still some optimizations to be done here with regards to bulk insertions/updates
        if current_host:
            if current_host == host:
                return HostAction.NO_CHANGE
            else:
                # logging.debug(f"Replaced host <{host['hostname']}> from source <{source}>")
                cursor.execute(
                    f"UPDATE {self.db_source_table} SET data = %s WHERE data->>'hostname' = %s AND data->'sources' ? %s",
                    [host.model_dump_json(), host.hostname, source],
                )
                return HostAction.UPDATE
        else:
            # logging.debug(f"Inserted host <{host['hostname']}> from source <{source}>")
            cursor.execute(
                f"INSERT INTO {self.db_source_table} (data) VALUES (%s)",
                [host.model_dump_json()],
            )
            return HostAction.INSERT

    def get_current_source_hosts(
        self, cursor: "Cursor", source: str
    ) -> Dict[str, models.Host]:
        hosts = {}  # type: Dict[str, models.Host]
        cursor.execute(
            f"SELECT data FROM {self.db_source_table} WHERE data->'sources' ? %s",
            [source],
        )
        for result in cursor.fetchall():
            try:
                host = models.Host(**result[0])
            except ValidationError as e:
                # TODO: ensure this actually identifies the faulty host
                logging.exception("Invalid host in source hosts table: %s", e)
            except Exception as e:
                logging.exception(
                    "Error when parsing host from source hosts table: %s", e
                )
            else:
                hosts[host.hostname] = host
        return hosts

    def handle_source_hosts(self, source: str, hosts: List[models.Host]) -> None:
        start_time = time.time()

        actions = Counter()  # type: Counter[HostAction]

        source_hostnames = {host.hostname for host in hosts}
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT DISTINCT data->>'hostname' FROM {self.db_source_table} WHERE data->'sources' ? %s",
                [source],
            )
            current_hostnames = {t[0] for t in db_cursor.fetchall()}

        removed_hostnames = current_hostnames - source_hostnames
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            for removed_hostname in removed_hostnames:
                db_cursor.execute(
                    f"DELETE FROM {self.db_source_table} WHERE data->>'hostname' = %s AND data->'sources' ? %s",
                    [removed_hostname, source],
                )
                actions[HostAction.DELETE] += 1

        with self.db_connection, self.db_connection.cursor() as db_cursor:
            current_hosts = self.get_current_source_hosts(db_cursor, source)
            for host in hosts:
                current_host = current_hosts.get(host.hostname)
                action = self.handle_source_host(db_cursor, host, current_host, source)
                actions[action] += 1

        logging.info(
            "Done handling hosts from source, '%s', in %.2f seconds. Equal hosts: %d, replaced hosts: %d, inserted hosts: %d, removed hosts: %d. Next update: %s",
            source,
            time.time() - start_time,
            actions[HostAction.NO_CHANGE],
            actions[HostAction.UPDATE],
            actions[HostAction.INSERT],
            actions[HostAction.DELETE],
            self.next_update.isoformat(timespec="seconds"),
        )


class SourceMergerProcess(BaseProcess):
    def __init__(
        self,
        name: str,
        state: State,
        db_uri: str,
        host_modifiers: List[HostModifier],
    ) -> None:
        super().__init__(name, state)

        self.db_uri = db_uri
        self.db_source_table = "hosts_source"
        self.db_hosts_table = "hosts"
        self.host_modifiers = host_modifiers

        try:
            self.db_connection = psycopg2.connect(self.db_uri)
            # TODO: Test connection? Cursor?
        except psycopg2.OperationalError:
            logging.error("Unable to connect to database. Process exiting with error")
            sys.exit(1)

        self.update_interval = 60

    def work(self) -> None:
        self.merge_sources()

    def merge_hosts(self, hosts: List[models.Host]) -> models.Host:
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
        cursor: "Cursor",
        current_host: Optional[models.Host],
        source_hosts: List[models.Host],
    ) -> HostAction:
        host = self.merge_hosts(source_hosts)

        for host_modifier in self.host_modifiers:
            try:
                modified_host = host_modifier.module.modify(host.model_copy(deep=True))
                assert isinstance(
                    modified_host, models.Host
                ), f"Modifier returned invalid type: {type(modified_host)}"
                assert (
                    host.hostname == modified_host.hostname
                ), f"Modifier changed the hostname, '{host.hostname}' -> '{modified_host.hostname}'"
                # Re-validate the host after modification
                host = host.model_validate(modified_host)
            except AssertionError as e:
                logging.warning(
                    "Host, '%s', was modified to be invalid by modifier: '%s'. Error: %s",
                    host.hostname,
                    host_modifier.name,
                    str(e),
                )
            except Exception as e:
                logging.warning(
                    "Error when running modifier %s on host '%s': %s",
                    host_modifier.name,
                    host.hostname,
                    str(e),
                )
                # TODO: Do more?

        if current_host:
            if current_host == host:
                # logging.debug(f"Host <{host['hostname']}> from source <{source}> is equal to current host")
                return HostAction.NO_CHANGE
            else:
                # logging.debug(f"Replaced host <{host['hostname']}> from source <{source}>")
                cursor.execute(
                    f"UPDATE {self.db_hosts_table} SET data = %s WHERE data->>'hostname' = %s",
                    [host.model_dump_json(), host.hostname],
                )
                return HostAction.UPDATE
        else:
            # logging.debug(f"Inserted host <{host['hostname']}> from source <{source}>")
            cursor.execute(
                f"INSERT INTO {self.db_hosts_table} (data) VALUES (%s)",
                [host.model_dump_json()],
            )
            return HostAction.INSERT

    def get_source_hosts(self, cursor: "Cursor") -> Dict[str, List[models.Host]]:
        cursor.execute(f"SELECT data FROM {self.db_source_table}")
        source_hosts = defaultdict(list)  # type: Dict[str, List[models.Host]]
        for host in cursor.fetchall():
            try:
                host_model = models.Host(**host[0])
            except ValidationError as e:
                # TODO: ensure this actually identifies the faulty host
                logging.exception("Invalid host in source hosts table: %s", e)
            except Exception as e:
                logging.exception(
                    "Error when parsing host from source hosts table: %s", e
                )
            else:
                source_hosts[host_model.hostname].append(host_model)
        return source_hosts

    def get_hosts(self, cursor: "Cursor") -> Dict[str, models.Host]:
        cursor.execute(f"SELECT data FROM {self.db_hosts_table}")
        hosts = {}  # type: Dict[str, models.Host]
        for host in cursor.fetchall():
            try:
                host_model = models.Host(**host[0])
            except ValidationError as e:
                # TODO: ensure this log actually identifies the faulty host
                logging.exception("Invalid host in hosts table: %s", e)
            except Exception as e:
                logging.exception("Error when parsing host from hosts table: %s", e)
            else:
                hosts[host_model.hostname] = host_model
        return hosts

    def merge_sources(self) -> None:
        start_time = time.time()
        logging.info("Merge starting")
        actions = Counter()  # type: Counter[HostAction]

        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT DISTINCT data->>'hostname' FROM {self.db_source_table}"
            )
            source_hostnames = {t[0] for t in db_cursor.fetchall()}
            db_cursor.execute(
                f"SELECT DISTINCT data->>'hostname' FROM {self.db_hosts_table}"
            )
            current_hostnames = {t[0] for t in db_cursor.fetchall()}

        # TODO: refactor to bulk delete
        removed_hostnames = current_hostnames - source_hostnames
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            for removed_hostname in removed_hostnames:
                if self.stop_event.is_set():
                    logging.debug("Told to stop. Breaking")
                    break
                db_cursor.execute(
                    f"DELETE FROM {self.db_hosts_table} WHERE data->>'hostname' = %s",
                    [removed_hostname],
                )
                actions[HostAction.DELETE] += 1

        # Update all hosts in a single transaction for performance
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            source_hosts_map = self.get_source_hosts(db_cursor)
            hosts = self.get_hosts(db_cursor)
            for hostname in source_hostnames:
                # NOTE: Should we finish handling all hosts before stopping?
                if self.stop_event.is_set():
                    logging.debug("Told to stop. Breaking")
                    break

                source_hosts = source_hosts_map.get(hostname)
                host = hosts.get(hostname)
                if not source_hosts:
                    logging.warning(
                        "Host '%s' not found in source hosts table", hostname
                    )
                    continue

                host_action = self.handle_host(db_cursor, host, source_hosts)
                actions[host_action] += 1

        logging.info(
            "Done with merge in %.2f seconds. Equal hosts: %d, replaced hosts: %d, inserted hosts: %d, removed hosts: %d. Next update: %s",
            time.time() - start_time,
            actions[HostAction.NO_CHANGE],
            actions[HostAction.UPDATE],
            actions[HostAction.INSERT],
            actions[HostAction.DELETE],
            self.next_update.isoformat(timespec="seconds"),
        )


class ZabbixUpdater(BaseProcess):
    def __init__(
        self, name: str, state: State, db_uri: str, settings: models.Settings
    ) -> None:
        super().__init__(name, state)

        self.db_uri = db_uri
        self.db_hosts_table = "hosts"

        try:
            self.db_connection = psycopg2.connect(self.db_uri)
            # TODO: Test connection? Cursor?
        except psycopg2.OperationalError as e:
            logging.error("Unable to connect to database. Process exiting with error")
            raise ZACException(*e.args)

        self.config = settings.zabbix
        self.settings = settings

        self.update_interval = 60  # default. Overriden in subclasses

        pyzabbix_logger = logging.getLogger("pyzabbix")
        pyzabbix_logger.setLevel(logging.ERROR)

        self.api = ZabbixAPI(
            self.config.url,
            timeout=self.config.timeout,  # timeout for connect AND read
            read_only=self.config.dryrun,  # prevent accidental changes
        )
        try:
            self.api.login(self.config.username, self.config.password)
        except httpx.ConnectError as e:
            logging.error("Error while connecting to Zabbix: %s", self.config.url)
            raise ZACException(*e.args)
        except httpx.TimeoutException as e:
            logging.error(
                "Timed out while connecting to Zabbix API: %s", self.config.url
            )
            raise ZACException(*e.args)
        except (ZabbixAPIException, httpx.HTTPError) as e:
            logging.error("Unable to login to Zabbix API: %s", str(e))
            raise ZACException(*e.args)

        self.property_template_map = utils.read_map_file(
            os.path.join(self.config.map_dir, "property_template_map.txt")
        )
        self.property_hostgroup_map = utils.read_map_file(
            os.path.join(self.config.map_dir, "property_hostgroup_map.txt")
        )
        self.siteadmin_hostgroup_map = utils.read_map_file(
            os.path.join(self.config.map_dir, "siteadmin_hostgroup_map.txt")
        )

        ver = self.api.apiinfo.version()
        self.zabbix_version = Version(ver)

    def work(self) -> None:
        start_time = time.time()
        logging.info("Zabbix update starting")
        self.do_update()
        logging.info(
            "Done with zabbix update in %.2f seconds. Next update: %s",
            time.time() - start_time,
            self.next_update.isoformat(timespec="seconds"),
        )

    def do_update(self) -> None:
        pass

    def get_db_hosts(self) -> Dict[str, models.Host]:
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT data FROM {self.db_hosts_table} WHERE data->>'enabled' = 'true'"
            )
            db_hosts = {}  # type: Dict[str, models.Host]
            for res in db_cursor.fetchall():
                try:
                    host = models.Host(**res[0])
                except ValidationError as e:
                    # TODO: log invalid host then remove it from the database
                    logging.exception("Invalid host in hosts table: %s", e)
                except Exception as e:
                    logging.exception("Error when parsing host from hosts table: %s", e)
                else:
                    db_hosts[host.hostname] = host
            return db_hosts

    def get_hostgroups(self, name: Optional[str] = None) -> List[HostGroup]:
        try:
            names = [name] if name else []
            hostgroups = self.api.get_hostgroups(*names)
        except ZabbixAPIException as e:
            raise ZACException("Error when fetching hostgroups: %s", e)
        return hostgroups


class ZabbixGarbageCollector(ZabbixUpdater):
    """Cleans up disabled hosts from maintenances and triggers in Zabbix."""

    def __init__(
        self, name: str, state: State, db_uri: str, settings: models.Settings
    ) -> None:
        super().__init__(name, state, db_uri, settings)

        self.update_interval = (
            self.settings.zac.process.garbage_collector.update_interval
        )

    def filter_disabled_hosts(
        self, model: ModelWithHosts
    ) -> Tuple[List[Host], List[Host]]:
        """Returns a tuple of (active_hosts, disabled_hosts) from a model."""
        keep: List[Host] = []
        remove: List[Host] = []
        for host in model.hosts:
            if str(host.status) == str(MonitoringStatus.OFF.value):
                remove.append(host)
            else:
                keep.append(host)
        return keep, remove

    def get_maintenances(self, disabled_hosts: List[Host]) -> List[Maintenance]:
        """Fetch all maintenances with disabled hosts in Zabbix."""
        return self.api.get_maintenances(hosts=disabled_hosts, select_hosts=True)

    def remove_disabled_hosts_from_maintenance(self, maintenance: Maintenance) -> None:
        """Remove all disabled hosts from a maintenance."""
        hosts_keep, hosts_remove = self.filter_disabled_hosts(maintenance)

        if self.config.dryrun:
            logging.info(
                "DRYRUN: Removing disabled hosts from maintenance '%s': %s",
                maintenance.name,
                ", ".join([host.host for host in hosts_remove]),
            )
            return

        # No disabled hosts in maintenance (Should never happen)
        if len(hosts_keep) == len(maintenance.hosts):
            logging.debug("No disabled hosts in maintenance '%s'", maintenance.name)
        # No hosts left in maintenance
        elif not hosts_keep:
            if self.settings.zac.process.garbage_collector.delete_empty_maintenance:
                self.delete_maintenance(maintenance)
            else:
                logging.error(
                    "Unable to remove disabled hosts from maintenance '%s': no hosts left. Delete maintenance manually.",
                    maintenance.name,
                )
        else:
            self.api.update_maintenance(maintenance, hosts_keep)
            logging.info(
                "Removed disabled hosts from maintenance '%s': %s",
                maintenance.name,
                ", ".join([host.host for host in hosts_remove]),
            )

    def delete_maintenance(self, maintenance: Maintenance) -> None:
        """Delete a maintenance in Zabbix."""
        if self.config.dryrun:
            logging.info("DRYRUN: Deleting maintenance '%s'", maintenance.name)
            return
        self.api.delete_maintenance(maintenance)
        logging.info("Deleted maintenance '%s'", maintenance.name)

    def remove_disabled_hosts_from_trigger(self, trigger: Trigger) -> None:
        """Remove all disabled hosts from a trigger."""
        hosts_keep, hosts_remove = self.filter_disabled_hosts(trigger)
        # No disabled hosts in trigger (Should never happen)
        if len(hosts_keep) == len(trigger.hosts):
            logging.debug("No disabled hosts in trigger '%s'", trigger.description)
            return
        # No hosts left in trigger
        elif not hosts_keep:
            logging.error(
                "Unable to remove disabled hosts from trigger '%s': no hosts left. Delete trigger manually.",
                trigger.description,
            )
            return

        if self.config.dryrun:
            logging.info(
                "DRYRUN: Removing disabled hosts from trigger '%s': %s",
                trigger.description,
                ", ".join([host.host for host in hosts_remove]),
            )
            return

        self.api.update_trigger(trigger, hosts_keep)
        logging.info(
            "Removed disabled hosts from trigger '%s': %s",
            trigger.description,
            ", ".join([host.host for host in hosts_remove]),
        )

    def cleanup_maintenances(self, disabled_hosts: List[Host]) -> None:
        maintenances = self.api.get_maintenances(
            hosts=disabled_hosts, select_hosts=True
        )
        for maintenance in maintenances:
            self.remove_disabled_hosts_from_maintenance(maintenance)

    def cleanup_triggers(self, disabled_hosts: List[Host]) -> None:
        triggers = self.api.get_triggers(hosts=disabled_hosts)
        for trigger in triggers:
            self.remove_disabled_hosts_from_trigger(trigger)

    def do_update(self) -> None:
        if not self.settings.zac.process.garbage_collector.enabled:
            logging.debug("Garbage collection is disabled")
            return
        # Get all disabled hosts
        disabled_hosts = self.api.get_hosts(status=MonitoringStatus.OFF)
        self.cleanup_maintenances(disabled_hosts)
        self.cleanup_triggers(disabled_hosts)


class ZabbixHostUpdater(ZabbixUpdater):
    def __init__(
        self, name: str, state: State, db_uri: str, settings: models.Settings
    ) -> None:
        super().__init__(name, state, db_uri, settings)

        self.update_interval = self.settings.zac.process.host_updater.update_interval

        # Fetch required host groups on startup
        self.disabled_hostgroup = self.get_or_create_hostgroup(
            self.config.hostgroup_disabled
        )
        self.enabled_hostgroup = self.get_or_create_hostgroup(self.config.hostgroup_all)

    def get_or_create_hostgroup(self, hostgroup: str) -> HostGroup:
        """Fetch a host group, creating it if it doesn't exist."""
        try:
            return self.api.get_hostgroup(hostgroup)
        except ZabbixNotFoundError:
            logging.info("Hostgroup '%s' not found. Creating it.", hostgroup)
            self.api.create_hostgroup(hostgroup)
            return self.api.get_hostgroup(hostgroup)

    def get_maintenances(self, zabbix_host: Host) -> List[Maintenance]:
        params = {
            "hostids": zabbix_host.hostid,
            "selectHosts": "extend",
            "output": "extend",
        }

        try:
            maintenances = self.api.get_maintenances(
                hosts=[zabbix_host],
                select_hosts=True,
            )
            maintenances = self.api.maintenance.get(**params)
        except ZabbixAPIException as e:
            logging.error(
                "Error when fetching maintenances for host '%s' (%s): %s",
                zabbix_host.host,
                zabbix_host.hostid,
                e.args,
            )
            maintenances = []
        return maintenances

    def do_remove_host_from_maintenance(
        self, zabbix_host: Host, maintenance: Maintenance
    ) -> None:
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Removing host %s from maintenance %s",
                zabbix_host.host,
                maintenance.name,
            )
            return

        # Determine new hosts list for maintenance
        new_hosts = [
            host for host in maintenance.hosts if host.hostid != zabbix_host.hostid
        ]

        if not new_hosts:
            # NOTE: ZabbixGarbageCollector cleans this up if enabled
            logging.info(
                "Maintenance '%s' is empty would be empty if removing host '%s'. Skipping.",
                zabbix_host.host,
                maintenance.name,
            )
            return

        try:
            self.api.update_maintenance(maintenance, hosts=new_hosts)
        except ZabbixAPIException as e:
            logging.error(
                "Error when removing host '%s' from maintenance '%s': %s",
                zabbix_host.host,
                maintenance.name,
                e.args,
            )
        else:
            logging.info(
                "Removed host %s from maintenance %s",
                zabbix_host.host,
                maintenance.name,
            )

    def remove_host_from_maintenances(self, zabbix_host: Host) -> None:
        maintenances = self.get_maintenances(zabbix_host)
        for maintenance in maintenances:
            self.do_remove_host_from_maintenance(zabbix_host, maintenance)

    def disable_host(self, zabbix_host: Host) -> None:
        # Host needs to be removed from all maintenances before it is disabled
        self.remove_host_from_maintenances(zabbix_host)
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Disabling host: '%s' (%s)",
                zabbix_host.host,
                zabbix_host.hostid,
            )
            return

        try:
            self.api.update_host(
                zabbix_host,
                status=MonitoringStatus.OFF,
                templates=[],
                groups=[self.disabled_hostgroup],
            )
        except ZabbixAPIException as e:
            logging.error(
                "Error when disabling host '%s' (%s): %s",
                zabbix_host.host,
                zabbix_host.hostid,
                e.args,
            )
        else:
            logging.info(
                "Disabled host: '%s' (%s)",
                zabbix_host.host,
                zabbix_host.hostid,
            )

    def enable_host(self, db_host: models.Host) -> None:
        # TODO: Set correct proxy when enabling
        hostname = db_host.hostname
        if self.config.dryrun:
            logging.info("DRYRUN: Enabling host: '%s'", hostname)
            return

        try:
            hosts = self.api.get_hosts(hostname, search=False)

            if hosts:
                host = hosts[0]
                self.api.update_host(
                    host, status=MonitoringStatus.ON, groups=[self.enabled_hostgroup]
                )
                logging.info("Enabled old host: '%s' (%s)", host.host, host.hostid)
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
                logging.info("Enabled new host: '%s' (%s)", hostname, hostid)
        except ZabbixAPIException as e:
            logging.error(
                "Error when enabling/creating host '%s': %s", hostname, e.args
            )

    def clear_proxy(self, zabbix_host: Host) -> None:
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Clearing proxy on host: '%s' (%s)",
                zabbix_host.host,
                zabbix_host.hostid,
            )
            return
        try:
            self.api.clear_host_proxy(zabbix_host)
        except ZabbixAPIException as e:
            logging.error("%s", e)  # Just log the error verbatim
        else:
            logging.info("Cleared proxy on host %s", zabbix_host)

    def set_interface(
        self,
        zabbix_host: Host,
        interface: models.Interface,
        useip: bool,
        old_interface: Optional[HostInterface] = None,
    ) -> None:
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Setting interface (type: %d) on host: %s",
                interface.type,
                zabbix_host,
            )
            return

        if useip:
            dns = None
            ip = interface.endpoint
        else:
            dns = interface.endpoint
            ip = None
        ifacetype = InterfaceType(interface.type)

        # Update existing interface
        if old_interface:
            if interface.details:
                details = UpdateHostInterfaceDetails.model_validate(interface.details)
            else:
                details = None

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
            logging.info(
                "Updating old interface (type: %s) on host: %s",
                interface.type,
                zabbix_host,
            )
        # Create new interface
        else:
            if interface.details:
                details = CreateHostInterfaceDetails.model_validate(interface.details)
            else:
                details = None
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
            logging.info(
                "Creating new interface (type: %s) on host: %s",
                interface.type,
                zabbix_host,
            )

    def set_inventory_mode(
        self, zabbix_host: Host, inventory_mode: InventoryMode
    ) -> None:
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Setting inventory_mode (%d) on host: %s",
                inventory_mode,
                zabbix_host,
            )
            return

        self.api.update_host(zabbix_host, inventory_mode=inventory_mode)
        logging.info(
            "Setting inventory_mode (%d) on host: %s", inventory_mode, zabbix_host
        )

    def set_inventory(self, zabbix_host: Host, inventory: Dict[str, str]) -> None:
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Setting inventory (%s) on host: %s", inventory, zabbix_host
            )
            return
        # TODO: refactor. Move everything in to ZabbixAPI.update_host?
        self.api.update_host_inventory(zabbix_host, inventory)
        logging.info("Setting inventory (%s) on host: %s", inventory, zabbix_host)

    def set_proxy(self, zabbix_host: Host, zabbix_proxy: Proxy) -> None:
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Setting proxy %s on host %s", zabbix_proxy.name, zabbix_host
            )
            return
        try:
            self.api.update_host_proxy(zabbix_host, zabbix_proxy)
        except ZabbixAPIException as e:
            logging.error(
                "Failed to set proxy %s on host %s: %s",
                zabbix_proxy.name,
                zabbix_host,
                e,
            )
        else:
            logging.info("Set proxy %s on host %s", zabbix_proxy.name, zabbix_host)

    def set_tags(self, zabbix_host: Host, tags: ZacTags) -> None:
        if self.config.dryrun:
            logging.info(
                "DRYRUN: Setting tags (%s) on host: %s",
                tags,
                zabbix_host,
            )
            return
        zabbix_tags = utils.zac_tags2zabbix_tags(tags)
        try:
            self.api.update_host(zabbix_host, tags=zabbix_tags)
        except ZabbixAPIException as e:
            logging.error(
                "Failed to set tags (%s) on host %s: %s", tags, zabbix_host, e
            )
        else:
            logging.info("Set tags (%s) on host: %s", tags, zabbix_host)

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
        )
        zabbix_hosts = {host.host: host for host in zhosts}

        zproxies = self.api.get_proxies()
        zabbix_proxies = {proxy.name: proxy for proxy in zproxies}
        if not zabbix_proxies:
            logging.warning("No Zabbix proxies found.")

        zabbix_managed_hosts: List[Host] = []
        zabbix_manual_hosts: List[Host] = []

        for hostname, host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            hostgroup_names = [group.name for group in host.groups]
            if self.config.hostgroup_manual in hostgroup_names:
                zabbix_manual_hosts.append(host)
            else:
                zabbix_managed_hosts.append(host)

        db_hostnames = set(db_hosts.keys())
        zabbix_hostnames = set(zabbix_hosts.keys())
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

        logging.debug("Total in zabbix: %d", len(zabbix_hostnames))
        logging.debug("Total in db: %d", len(db_hostnames))
        logging.debug("Manual in zabbix: %d", len(zabbix_manual_hostnames))
        logging.debug("Manual and in source: %d", len(hostnames_in_manual_and_source))
        logging.debug(
            "Manual and in source: %s", " ".join(hostnames_in_manual_and_source[:10])
        )
        logging.debug("Only in zabbix: %d", len(hostnames_to_remove))
        logging.debug("Only in zabbix: %s", " ".join(hostnames_to_remove[:10]))
        logging.debug("Only in db: %d", len(hostnames_to_add))
        logging.debug("Only in db: %s", " ".join(hostnames_to_add[:10]))
        logging.debug("In both: %d", len(hostnames_in_both))

        # Check if we have too many hosts to add/remove
        check_failsafe(self.settings, hostnames_to_add, hostnames_to_remove)

        for hostname in hostnames_to_remove:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            zabbix_host = zabbix_hosts[hostname]
            self.disable_host(zabbix_host)

        for hostname in hostnames_to_add:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            db_host = db_hosts[hostname]
            self.enable_host(db_host)

        for hostname in hostnames_in_both:
            # Check if these hosts are good

            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            db_host = db_hosts[hostname]
            zabbix_host = zabbix_hosts[hostname]

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
                    logging.error(
                        "Proxy pattern ('%s') for host, '%s' (%s), doesn't match any proxies.",
                        db_host.proxy_pattern,
                        hostname,
                        zabbix_host.hostid,
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
                            # This DNS interface is configured wrong, set it
                            self.set_interface(
                                zabbix_host,
                                interface,
                                useip,
                                zabbix_interface,
                            )
                        if interface.type == 2 and interface.details:
                            details_dict = zabbix_interface.model_dump()
                            # Check that the interface details are correct.
                            # Note that the Zabbix API response may include more
                            # information than our back-end; ignore such keys.
                            if not all(
                                str(details_dict.get(k, None)) == str(v)
                                for k, v in interface.details.items()
                            ):
                                # This SNMP interface is configured wrong, set it.
                                self.set_interface(
                                    zabbix_host,
                                    interface,
                                    useip,
                                    zabbix_interface,
                                )

                    if interface.type in zabbix_interfaces:
                        # This interface type exists on the current zabbix host
                        # TODO: This logic could probably be simplified and should be refactored
                        zabbix_interface = zabbix_interfaces[interface.type]
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
                            # This DNS interface is configured wrong, set it
                            self.set_interface(
                                zabbix_host,
                                interface,
                                useip,
                                zabbix_interface,
                            )
                        if interface.type == 2 and interface.details:
                            details_dict = zabbix_interface.model_dump()
                            # Check that the interface details are correct.
                            # Note that the Zabbix API response may include more
                            # information than our back-end; ignore such keys.
                            if not all(
                                str(details_dict.get(k, None)) == str(v)
                                for k, v in interface.details.items()
                            ):
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
                    if not tag.tag.startswith(self.config.tags_prefix)
                ]
            )  # These are tags outside our namespace/prefix. Keep them.
            current_tags = utils.zabbix_tags2zac_tags(
                [
                    tag
                    for tag in zabbix_host.tags
                    if tag.tag.startswith(self.config.tags_prefix)
                ]
            )
            db_tags = db_host.tags
            ignored_tags = set(
                filter(
                    lambda tag: not tag[0].startswith(self.config.tags_prefix), db_tags
                )
            )
            if ignored_tags:
                db_tags = db_tags - ignored_tags
                logging.warning(
                    "Tags (%s) not matching tags prefix ('%s') is configured on host %s. They will be ignored.",
                    ignored_tags,
                    self.config.tags_prefix,
                    zabbix_host,
                )

            tags_to_remove = current_tags - db_tags
            tags_to_add = db_tags - current_tags
            tags = db_tags.union(other_zabbix_tags)
            if tags_to_remove or tags_to_add:
                if tags_to_remove:
                    logging.debug(
                        "Going to remove tags '%s' from host %s.",
                        tags_to_remove,
                        zabbix_host,
                    )
                if tags_to_add:
                    logging.debug(
                        "Going to add tags '%s' to host %s.",
                        tags_to_add,
                        zabbix_host,
                    )
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
                        if k not in self.config.managed_inventory
                    }

                    # inventories managed by zac and to be updated
                    inventory = {
                        k: v
                        for k, v in changed_inventory.items()
                        if k in self.config.managed_inventory
                    }
                    if inventory:
                        self.set_inventory(zabbix_host, inventory)
                    if ignored_inventory:
                        logging.warning(
                            "Zac is not configured to manage inventory properties: '%s'.",
                            ignored_inventory,
                        )


class ZabbixTemplateUpdater(ZabbixUpdater):
    def __init__(
        self, name: str, state: State, db_uri: str, settings: models.Settings
    ) -> None:
        super().__init__(name, state, db_uri, settings)
        self.update_interval = (
            self.settings.zac.process.template_updater.update_interval
        )

    def clear_templates(self, templates: List[Template], host: Host) -> None:
        if self.config.dryrun:
            logging.debug(
                "DRYRUN: Clearing templates %s on host: %s",
                ", ".join(t.host for t in templates),
                host,
            )
            return

        try:
            self.api.unlink_templates_from_hosts(templates, [host], clear=True)
        except ZabbixAPIException as e:
            logging.error("Error when clearing templates on host %s: %s", host, e)
        else:
            logging.info(
                "Cleared templates %s on host: %s",
                ", ".join(t.host for t in templates),
                host,
            )

    def set_templates(self, templates: List[Template], host: Host) -> None:
        # For logging
        to_add = ", ".join(f"{t.host!r}" for t in templates)

        if self.config.dryrun:
            logging.debug("DRYRUN: Setting templates %s on host: %s", to_add, host)
            return

        try:
            self.api.link_templates_to_hosts(templates, [host])
        except ZabbixAPIException as e:
            logging.error("Error when setting templates on host %s: %s", host, e)
        else:
            logging.info("Set templates %s on host: %s", to_add, host)

    def do_update(self) -> None:
        # Determine names of templates we are managing
        managed_template_names = set(
            itertools.chain.from_iterable(self.property_template_map.values())
        )
        zabbix_templates = {}
        for zabbix_template in self.api.template.get(output=["host", "templateid"]):
            zabbix_templates[zabbix_template["host"]] = zabbix_template["templateid"]
        managed_template_names = managed_template_names.intersection(
            set(zabbix_templates.keys())
        )  # If the template isn't in zabbix we can't manage it

        # Get hosts from DB
        db_hosts = self.get_db_hosts()

        # Get hosts from Zabbix
        _hosts = self.api.get_hosts(
            status=MonitoringStatus.ON,
            flags=0,
            select_groups=True,
            select_templates=True,
        )
        zabbix_hosts = {host.host: host for host in _hosts}

        for zabbix_hostname, zabbix_host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            # Manually managed host - skip it
            if self.config.hostgroup_manual in [
                group.name for group in zabbix_host.groups
            ]:
                logging.debug("Skipping manual host: %s", zabbix_host)
                continue

            # Disabled hosts are not managed
            if zabbix_hostname not in db_hosts:
                logging.debug(
                    "Skipping host (It is not enabled in the database): %s", zabbix_host
                )
                continue

            db_host = db_hosts[zabbix_hostname]

            # Determine managed templates
            synced_template_names = set()
            for prop in db_host.properties:
                if template_names := self.property_template_map.get(prop):
                    synced_template_names.update(template_names)
            synced_template_names = synced_template_names.intersection(
                set(zabbix_templates.keys())
            )  # If the template isn't in zabbix we can't manage it

            host_templates: Dict[str, Template] = {}
            for zabbix_template in zabbix_host.parent_templates:
                host_templates[zabbix_template.host] = zabbix_template

            old_host_templates = host_templates.copy()
            host_templates_to_remove: Dict[str, Template] = {}

            # Update templates on host
            for template_name in list(host_templates.keys()):
                if (
                    template_name in managed_template_names
                    and template_name not in synced_template_names
                ):
                    logging.debug(
                        "Going to remove template '%s' from host '%s'.",
                        template_name,
                        zabbix_hostname,
                    )
                    host_templates_to_remove[template_name] = host_templates[
                        template_name
                    ]
                    del host_templates[template_name]
            for template_name in synced_template_names:
                if template_name not in host_templates.keys():
                    logging.debug(
                        "Going to add template '%s' to host '%s'.",
                        template_name,
                        zabbix_hostname,
                    )
                    host_templates[template_name] = zabbix_templates[template_name]
            if host_templates != old_host_templates:
                logging.info(
                    "Updating templates on host '%s'. Old: %s. New: %s",
                    zabbix_hostname,
                    ", ".join(old_host_templates.keys()),
                    ", ".join(host_templates.keys()),
                )
                if host_templates_to_remove:
                    self.clear_templates(
                        list(host_templates_to_remove.values()), zabbix_host
                    )
                # TODO: Setting templates might not be necessary if we only removed templates. Consider refactor
                # TODO: Setting templates should not be performed if template clearing has failed (will lead to unlink without clear)
                self.set_templates(list(host_templates.values()), zabbix_host)


class ZabbixHostgroupUpdater(ZabbixUpdater):
    def __init__(
        self, name: str, state: State, db_uri: str, settings: models.Settings
    ) -> None:
        super().__init__(name, state, db_uri, settings)
        self.update_interval = (
            self.settings.zac.process.hostgroup_updater.update_interval
        )

    def set_hostgroups(self, host: Host, hostgroups: List[HostGroup]) -> None:
        """Set host groups on a host given a list of host groups."""
        to_add = ", ".join(f"{hg.name!r}" for hg in hostgroups)
        if self.config.dryrun:
            logging.debug("DRYRUN: Setting hostgroups %s on host: %s", to_add, host)
            return
        try:
            self.api.set_host_hostgroups(host, hostgroups)
        except ZabbixAPIException as e:
            logging.error("Error when setting hostgroups on host %s: %s", host, e)
        else:
            logging.info("Set hostgroups %s on host: %s", to_add, host)

    def create_hostgroup(self, hostgroup_name: str) -> Optional[str]:
        if self.config.dryrun:
            logging.debug("DRYRUN: Creating hostgroup: '%s'", hostgroup_name)
            return None

        logging.debug("Creating hostgroup: '%s'", hostgroup_name)
        try:
            groupid = self.api.create_hostgroup(hostgroup_name)
            logging.info("Created host group '%s' (%s)", hostgroup_name, groupid)
            return groupid
        except ZabbixAPIException as e:
            logging.error("Error when creating hostgroups '%s': %s", hostgroup_name, e)
            return None

    def create_extra_hostgroups(self, existing_hostgroups: List[HostGroup]) -> None:
        """Creates additonal host groups based on the prefixes specified
        in the config file. These host groups are not assigned hosts by ZAC."""
        hostgroup_names = set(h.name for h in existing_hostgroups)

        for prefix in self.config.extra_siteadmin_hostgroup_prefixes:
            mapping = utils.mapping_values_with_prefix(
                self.siteadmin_hostgroup_map,  # this is copied in the function
                prefix=prefix,
            )
            for hostgroups in mapping.values():
                for hostgroup in hostgroups:
                    if hostgroup in hostgroup_names:
                        continue
                    self.create_hostgroup(hostgroup)

    def create_templategroup(self, templategroup_name: str) -> Optional[str]:
        if self.config.dryrun:
            logging.debug("DRYRUN: Creating template group: '%s'", templategroup_name)
            return None

        logging.debug("Creating template group: '%s'", templategroup_name)
        try:
            groupid = self.api.create_templategroup(templategroup_name)
            logging.info(
                "Created template group '%s' (%s)", templategroup_name, groupid
            )
            return groupid
        except ZabbixAPIException as e:
            logging.error(
                "Error when creating template group '%s': %s", templategroup_name, e
            )
            return None

    def create_templategroups(self, existing_hostgroups: List[HostGroup]) -> None:
        """Creates template groups for each host group in the siteadmin
        mapping file with the configured template group prefix.

        For Zabbix <6.2, host groups are created instead of template groups."""
        # Construct a set of all template group names from siteadmin mapping file
        # by replacing the host group prefix with the template group prefix
        tgroups = set(
            utils.with_prefix(tg, self.config.templategroup_prefix)
            for tg in itertools.chain.from_iterable(
                self.siteadmin_hostgroup_map.values()
            )
        )
        if compat.templategroups_supported(self.zabbix_version):
            logging.debug(
                "Zabbix version is %s. Will create template groups.",
                self.zabbix_version,
            )
            self._create_templategroups(tgroups)
        else:
            logging.debug(
                "Zabbix version is %s. Will create host groups instead of template groups.",
                self.zabbix_version,
            )
            self._create_templategroups_pre_62_compat(tgroups, existing_hostgroups)

    def _create_templategroups(self, tgroups: Set[str]) -> None:
        """Create the given template groups if they don't exist.

        Args:
            tgroups: A set of template group names to create.
        """
        res = self.api.get_templategroups()
        existing_tgroups = set(tg.name for tg in res)
        for tgroup in tgroups:
            if tgroup in existing_tgroups:
                continue
            self.create_templategroup(tgroup)

    def _create_templategroups_pre_62_compat(
        self, tgroups: Set[str], existing_hostgroups: List[HostGroup]
    ) -> None:
        """Compatibility method for creating template groups on Zabbix <6.2.

        Because template groups do not exist in <6.2, we instead create
        host groups with the given names.

        Args:
            tgroups: A set of host group names to create.
        """
        existing_hgroup_names = set(h.name for h in existing_hostgroups)
        for tgroup in tgroups:
            if tgroup in existing_hgroup_names:
                continue
            self.create_hostgroup(tgroup)

    def do_update(self) -> None:
        managed_hostgroup_names = set(
            itertools.chain.from_iterable(self.property_hostgroup_map.values())
        )  # type: Set[str]
        managed_hostgroup_names.update(
            itertools.chain.from_iterable(self.siteadmin_hostgroup_map.values())
        )

        existing_hostgroups = self.api.get_hostgroups()

        # Create extra host groups if necessary
        if self.config.extra_siteadmin_hostgroup_prefixes:
            self.create_extra_hostgroups(existing_hostgroups)

        # Create template groups if enabled
        if self.config.create_templategroups:
            self.create_templategroups(existing_hostgroups)

        zabbix_hostgroups: Dict[str, HostGroup] = {}  # type: Dict[str, str]
        for zabbix_hostgroup in existing_hostgroups:
            zabbix_hostgroups[zabbix_hostgroup.name] = zabbix_hostgroup
            if zabbix_hostgroup.name.startswith(self.config.hostgroup_source_prefix):
                managed_hostgroup_names.add(zabbix_hostgroup.name)
            if zabbix_hostgroup.name.startswith(
                self.config.hostgroup_importance_prefix
            ):
                managed_hostgroup_names.add(zabbix_hostgroup.name)
        managed_hostgroup_names.update([self.config.hostgroup_all])

        # Get hosts from DB
        db_hosts = self.get_db_hosts()

        # Get hosts from Zabbix
        _hosts = self.api.get_hosts(
            status=MonitoringStatus.ON,
            flags=0,
            select_groups=True,
            select_templates=True,
        )
        zabbix_hosts = {host.host: host for host in _hosts}

        # Iterate over hosts in Zabbix and update synced hosts
        for zabbix_hostname, zabbix_host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            # Host is manually managed - skip it
            if self.config.hostgroup_manual in [
                group.name for group in zabbix_host.groups
            ]:
                logging.debug("Skipping manual host: %s", zabbix_host)
                continue

            # Disabled hosts are not managed
            if zabbix_hostname not in db_hosts:
                logging.debug(
                    "Skipping host (It is not enabled in the database): %s", zabbix_host
                )
                continue

            db_host = db_hosts[zabbix_hostname]

            # Determine synced host groups for host
            synced_hostgroup_names = set([self.config.hostgroup_all])
            for _property in db_host.properties:
                if _property in self.property_hostgroup_map:
                    synced_hostgroup_names.update(
                        self.property_hostgroup_map[_property]
                    )
            for siteadmin in db_host.siteadmins:
                if siteadmin in self.siteadmin_hostgroup_map:
                    synced_hostgroup_names.update(
                        self.siteadmin_hostgroup_map[siteadmin]
                    )
            for source in db_host.sources:
                synced_hostgroup_names.add(
                    f"{self.config.hostgroup_source_prefix}{source}"
                )
            if db_host.importance is not None:
                synced_hostgroup_names.add(
                    f"{self.config.hostgroup_importance_prefix}{db_host.importance}"
                )
            else:
                synced_hostgroup_names.add(
                    f"{self.config.hostgroup_importance_prefix}X"
                )

            host_hostgroups: Dict[str, HostGroup] = {}
            for zabbix_hostgroup in zabbix_host.groups:
                host_hostgroups[zabbix_hostgroup.name] = zabbix_hostgroup
            old_host_hostgroups = host_hostgroups.copy()

            for hostgroup_name in list(host_hostgroups.keys()):
                # TODO: Here lies a bug due to managed_hostgroup_names not being properly updated above?
                if (
                    hostgroup_name in managed_hostgroup_names
                    and hostgroup_name not in synced_hostgroup_names
                ):
                    logging.debug(
                        "Going to remove hostgroup '%s' from host %s.",
                        hostgroup_name,
                        zabbix_host,
                    )
                    del host_hostgroups[hostgroup_name]

            # Update host groups for host
            # Creates synced host groups if they don't exist
            for hostgroup_name in synced_hostgroup_names:
                if hostgroup_name not in host_hostgroups.keys():
                    logging.debug(
                        "Going to add hostgroup '%s' to host %s.",
                        hostgroup_name,
                        zabbix_host,
                    )
                    zabbix_hostgroup = zabbix_hostgroups.get(hostgroup_name, None)
                    if not zabbix_hostgroup:
                        # The hostgroup doesn't exist. We need to create it.
                        zabbix_hostgroup_id = self.create_hostgroup(hostgroup_name)
                        # Add group to mapping so we don't try to create it again
                        if zabbix_hostgroup_id:
                            zabbix_hostgroups[hostgroup_name] = self.api.get_hostgroup(
                                hostgroup_name
                            )
                    if zabbix_hostgroup:
                        host_hostgroups[hostgroup_name] = zabbix_hostgroup

            # Compare names of host groups to see if they are changed
            if sorted(host_hostgroups) != sorted(old_host_hostgroups):
                logging.info(
                    "Updating host groups on host '%s'. Old: %s. New: %s",
                    zabbix_hostname,
                    ", ".join(old_host_hostgroups.keys()),
                    ", ".join(host_hostgroups.keys()),
                )
                self.set_hostgroups(zabbix_host, list(host_hostgroups.values()))
