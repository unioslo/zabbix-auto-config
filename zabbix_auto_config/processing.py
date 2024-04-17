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

import psycopg2
import pyzabbix
import requests.exceptions
from packaging.version import Version
from pydantic import ValidationError

from . import compat
from . import exceptions
from . import models
from . import utils
from ._types import HostModifier
from ._types import SourceCollectorModule
from ._types import ZacTags
from .errcount import RollingErrorCounter
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
                    if isinstance(e, requests.exceptions.Timeout):
                        logging.error("Timeout exception: %s", str(e))
                    elif isinstance(e, exceptions.ZACException):
                        logging.error("Work exception: %s", str(e))
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
                raise exceptions.ZACException(
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
            raise exceptions.ZACException(
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
            raise exceptions.SourceCollectorError(e) from e

        valid_hosts = []  # type: List[models.Host]
        for host in hosts:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            if not isinstance(host, models.Host):
                raise exceptions.SourceCollectorTypeError(
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
            raise exceptions.ZACException(*e.args)

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
            raise exceptions.ZACException(*e.args)

        self.config = settings.zabbix
        self.settings = settings

        self.update_interval = 60

        pyzabbix_logger = logging.getLogger("pyzabbix")
        pyzabbix_logger.setLevel(logging.ERROR)

        self.api = pyzabbix.ZabbixAPI(
            self.config.url,
            timeout=self.config.timeout,  # timeout for connect AND read
        )
        try:
            self.api.login(self.config.username, self.config.password)
        except requests.exceptions.ConnectionError as e:
            logging.error("Error while connecting to Zabbix: %s", self.config.url)
            raise exceptions.ZACException(*e.args)
        except (pyzabbix.ZabbixAPIException, requests.exceptions.HTTPError) as e:
            logging.error("Unable to login to Zabbix API: %s", str(e))
            raise exceptions.ZACException(*e.args)
        except requests.exceptions.Timeout as e:
            logging.error(
                "Timed out while connecting to Zabbix API: %s", self.config.url
            )
            raise exceptions.ZACException(*e.args)

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


class ZabbixHostUpdater(ZabbixUpdater):
    def disable_host(self, zabbix_host: Dict[str, Any]) -> None:
        if not self.config.dryrun:
            try:
                disabled_hostgroup_id = self.api.hostgroup.get(
                    filter={"name": self.config.hostgroup_disabled}
                )[0]["groupid"]
                self.api.host.update(
                    hostid=zabbix_host["hostid"],
                    status=1,
                    templates=[],
                    groups=[{"groupid": disabled_hostgroup_id}],
                )
                logging.info(
                    "Disabling host: '%s' (%s)",
                    zabbix_host["host"],
                    zabbix_host["hostid"],
                )
            except pyzabbix.ZabbixAPIException as e:
                logging.error(
                    "Error when disabling host '%s' (%s): %s",
                    zabbix_host["host"],
                    zabbix_host["hostid"],
                    e.args,
                )
            except IndexError:
                logging.critical(
                    "Disabled host group '%s' does not exist in Zabbix. Cannot disable host '%s'",
                    self.config.hostgroup_disabled,
                    zabbix_host.get("host"),
                )
                self.stop_event.set()
        else:
            logging.info(
                "DRYRUN: Disabling host: '%s' (%s)",
                zabbix_host["host"],
                zabbix_host["hostid"],
            )

    def enable_host(self, db_host: models.Host) -> None:
        # TODO: Set correct proxy when enabling
        hostname = db_host.hostname
        if not self.config.dryrun:
            try:
                hostgroup_id = self.api.hostgroup.get(
                    filter={"name": self.config.hostgroup_all}
                )[0]["groupid"]

                hosts = self.api.host.get(filter={"name": hostname})
                if hosts:
                    host = hosts[0]
                    self.api.host.update(
                        hostid=host["hostid"],
                        status=0,
                        groups=[{"groupid": hostgroup_id}],
                    )
                    logging.info(
                        "Enabling old host: '%s' (%s)", host["host"], host["hostid"]
                    )
                else:
                    interface = {
                        "dns": hostname,
                        "ip": "",
                        "useip": 0,
                        "type": 1,
                        "port": 10050,
                        "main": 1,
                    }
                    result = self.api.host.create(
                        host=hostname,
                        status=0,
                        groups=[{"groupid": hostgroup_id}],
                        interfaces=[interface],
                    )
                    logging.info(
                        "Enabling new host: '%s' (%s)", hostname, result["hostids"][0]
                    )
            except pyzabbix.ZabbixAPIException as e:
                logging.error(
                    "Error when enabling/creating host '%s': %s", hostname, e.args
                )
            except IndexError:
                logging.critical(
                    "Enabled host group '%s' does not exist in Zabbix. Cannot enable host '%s'",
                    self.config.hostgroup_all,
                    hostname,
                )
                self.stop_event.set()
        else:
            logging.info("DRYRUN: Enabling host: '%s'", hostname)

    def clear_proxy(self, zabbix_host: Dict[str, Any]) -> None:
        if not self.config.dryrun:
            kwargs = {
                "hostid": zabbix_host["hostid"],
                compat.host_proxyid(self.zabbix_version): "0",
            }
            self.api.host.update(**kwargs)
            logging.info(
                "Clearing proxy on host: '%s' (%s)",
                zabbix_host["host"],
                zabbix_host["hostid"],
            )
        else:
            logging.info(
                "DRYRUN: Clearing proxy on host: '%s' (%s)",
                zabbix_host["host"],
                zabbix_host["hostid"],
            )

    def set_interface(
        self,
        zabbix_host: Dict[str, Any],
        interface: models.Interface,
        useip: bool,
        old_id: Optional[str],
    ) -> None:
        if not self.config.dryrun:
            parameters = {
                "hostid": zabbix_host["hostid"],
                "main": 1,
                "port": interface.port,
                "type": interface.type,
                "useip": int(useip),
            }
            if useip:
                parameters["dns"] = ""
                parameters["ip"] = interface.endpoint
            else:
                parameters["dns"] = interface.endpoint
                parameters["ip"] = ""

            if interface.details:
                parameters["details"] = interface.details

            if old_id:
                self.api.hostinterface.update(interfaceid=old_id, **parameters)
                logging.info(
                    "Updating old interface (type: %s) on host: '%s' (%s)",
                    interface.type,
                    zabbix_host["host"],
                    zabbix_host["hostid"],
                )
            else:
                self.api.hostinterface.create(**parameters)
                logging.info(
                    "Creating new interface (type: %s) on host: '%s' (%s)",
                    interface.type,
                    zabbix_host["host"],
                    zabbix_host["hostid"],
                )
        else:
            logging.info(
                "DRYRUN: Setting interface (type: %d) on host: '%s' (%s)",
                interface.type,
                zabbix_host["host"],
                zabbix_host["hostid"],
            )

    def set_inventory_mode(
        self, zabbix_host: Dict[str, Any], inventory_mode: int
    ) -> None:
        if not self.config.dryrun:
            self.api.host.update(
                hostid=zabbix_host["hostid"], inventory_mode=inventory_mode
            )
            logging.info(
                "Setting inventory_mode (%d) on host: '%s' (%s)",
                inventory_mode,
                zabbix_host["host"],
                zabbix_host["hostid"],
            )
        else:
            logging.info(
                "DRYRUN: Setting inventory_mode (%d) on host: '%s' (%s)",
                inventory_mode,
                zabbix_host["host"],
                zabbix_host["hostid"],
            )

    def set_inventory(
        self, zabbix_host: Dict[str, Any], inventory: Dict[str, str]
    ) -> None:
        if not self.config.dryrun:
            self.api.host.update(hostid=zabbix_host["hostid"], inventory=inventory)
            logging.info(
                "Setting inventory (%s) on host: '%s'", inventory, zabbix_host["host"]
            )
        else:
            logging.info(
                "DRYRUN: Setting inventory (%s) on host: '%s'",
                inventory,
                zabbix_host["host"],
            )

    def set_proxy(
        self, zabbix_host: Dict[str, Any], zabbix_proxy: Dict[str, Any]
    ) -> None:
        if not self.config.dryrun:
            kwargs = {
                "hostid": zabbix_host["hostid"],
                compat.host_proxyid(self.zabbix_version): zabbix_proxy["proxyid"],
            }
            self.api.host.update(**kwargs)
            logging.info(
                "Setting proxy (%s) on host: '%s' (%s)",
                zabbix_proxy[compat.proxy_name(self.zabbix_version)],
                zabbix_host["host"],
                zabbix_host["hostid"],
            )
        else:
            logging.info(
                "DRYRUN: Setting proxy (%s) on host: '%s' (%s)",
                zabbix_proxy[compat.proxy_name(self.zabbix_version)],
                zabbix_host["host"],
                zabbix_host["hostid"],
            )

    def set_tags(self, zabbix_host: Dict[str, Any], tags: ZacTags) -> None:
        if not self.config.dryrun:
            zabbix_tags = utils.zac_tags2zabbix_tags(tags)
            self.api.host.update(hostid=zabbix_host["hostid"], tags=zabbix_tags)
            logging.info(
                "Setting tags (%s) on host: '%s' (%s)",
                tags,
                zabbix_host["host"],
                zabbix_host["hostid"],
            )
        else:
            logging.info(
                "DRYRUN: Setting tags (%s) on host: '%s' (%s)",
                tags,
                zabbix_host["host"],
                zabbix_host["hostid"],
            )

    def do_update(self) -> None:
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT data FROM {self.db_hosts_table} WHERE data->>'enabled' = 'true'"
            )
            db_hosts = {
                t[0]["hostname"]: models.Host(**t[0]) for t in db_cursor.fetchall()
            }
        # status:0 = monitored, flags:0 = non-discovered host
        kwargs = {
            "filter": {"status": 0, "flags": 0},
            "output": [
                "hostid",
                "host",
                "status",
                "flags",
                compat.host_proxyid(self.zabbix_version),
                "inventory_mode",
            ],
            "selectInterfaces": [
                "dns",
                "interfaceid",
                "ip",
                "main",
                "port",
                "type",
                "useip",
                "details",
            ],
            "selectInventory": self.config.managed_inventory,
            "selectParentTemplates": ["templateid", "host"],
            "selectTags": ["tag", "value"],
            compat.param_host_get_groups(self.zabbix_version): ["groupid", "name"],
        }
        zabbix_hosts = {host["host"]: host for host in self.api.host.get(**kwargs)}
        zabbix_proxies = {
            proxy[compat.proxy_name(self.zabbix_version)]: proxy
            for proxy in self.api.proxy.get(
                output=[
                    "proxyid",
                    compat.proxy_name(self.zabbix_version),
                    compat.proxy_operating_mode(self.zabbix_version),
                ]
            )
        }
        zabbix_managed_hosts = []
        zabbix_manual_hosts = []

        for hostname, host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            hostgroup_names = [
                group["name"]
                for group in host[compat.host_hostgroups(self.zabbix_version)]
            ]
            if self.config.hostgroup_manual in hostgroup_names:
                zabbix_manual_hosts.append(host)
            else:
                zabbix_managed_hosts.append(host)

        db_hostnames = set(db_hosts.keys())
        zabbix_hostnames = set(zabbix_hosts.keys())
        zabbix_managed_hostnames = {host["host"] for host in zabbix_managed_hosts}
        zabbix_manual_hostnames = {host["host"] for host in zabbix_manual_hosts}

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
            zabbix_proxy_id = zabbix_host[compat.host_proxyid(self.zabbix_version)]
            zabbix_proxy = [
                proxy
                for proxy in zabbix_proxies.values()
                if proxy["proxyid"] == zabbix_proxy_id
            ]
            current_zabbix_proxy = zabbix_proxy[0] if zabbix_proxy else None
            if db_host.proxy_pattern:
                possible_proxies = [
                    proxy
                    for proxy in zabbix_proxies.values()
                    if re.match(
                        db_host.proxy_pattern,
                        proxy[compat.proxy_name(self.zabbix_version)],
                    )
                ]
                if not possible_proxies:
                    logging.error(
                        "Proxy pattern ('%s') for host, '%s' (%s), doesn't match any proxies.",
                        db_host.proxy_pattern,
                        hostname,
                        zabbix_host["hostid"],
                    )
                else:
                    new_proxy = random.choice(possible_proxies)
                    if current_zabbix_proxy and not re.match(
                        db_host.proxy_pattern,
                        current_zabbix_proxy[compat.proxy_name(self.zabbix_version)],
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
                zabbix_interfaces = zabbix_host["interfaces"]

                # The API doesn't return the proper, documented types. We need to fix these types
                # https://www.zabbix.com/documentation/current/manual/api/reference/hostinterface/object
                for zabbix_interface in zabbix_interfaces:
                    zabbix_interface["type"] = int(zabbix_interface["type"])
                    zabbix_interface["main"] = int(zabbix_interface["main"])
                    zabbix_interface["useip"] = int(zabbix_interface["useip"])

                # Restructure object, and filter non main/default interfaces
                zabbix_interfaces = {
                    i["type"]: i for i in zabbix_host["interfaces"] if i["main"] == 1
                }

                for interface in db_host.interfaces:
                    # We assume that we're using an IP if the endpoint is a valid IP
                    useip = utils.is_valid_ip(interface.endpoint)
                    if interface.type in zabbix_interfaces:
                        # This interface type exists on the current zabbix host
                        # TODO: This logic could probably be simplified and should be refactored
                        zabbix_interface = zabbix_interfaces[interface.type]
                        if useip and (
                            zabbix_interface["ip"] != interface.endpoint
                            or zabbix_interface["port"] != interface.port
                            or zabbix_interface["useip"] != useip
                        ):
                            # This IP interface is configured wrong, set it
                            self.set_interface(
                                zabbix_host,
                                interface,
                                useip,
                                zabbix_interface["interfaceid"],
                            )
                        elif not useip and (
                            zabbix_interface["dns"] != interface.endpoint
                            or zabbix_interface["port"] != interface.port
                            or zabbix_interface["useip"] != useip
                        ):
                            # This DNS interface is configured wrong, set it
                            self.set_interface(
                                zabbix_host,
                                interface,
                                useip,
                                zabbix_interface["interfaceid"],
                            )
                        if interface.type == 2 and interface.details:
                            # Check that the interface details are correct.  Note
                            # that responses from the Zabbix API are quoted, so we
                            # need to convert our natively typed values to strings.
                            # Also note that the Zabbix API response may include more
                            # information than our back-end; ignore such keys.
                            # TODO: this is terrible and should be implemented
                            # using dataclasses for the interface and host types.
                            if not all(
                                zabbix_interface["details"].get(k, None) == str(v)
                                for k, v in interface.details.items()
                            ):
                                # This SNMP interface is configured wrong, set it.
                                self.set_interface(
                                    zabbix_host,
                                    interface,
                                    useip,
                                    zabbix_interface["interfaceid"],
                                )
                    else:
                        # This interface is missing, set it
                        self.set_interface(zabbix_host, interface, useip, None)

            # Check current tags and apply db tags
            other_zabbix_tags = utils.zabbix_tags2zac_tags(
                [
                    tag
                    for tag in zabbix_host["tags"]
                    if not tag["tag"].startswith(self.config.tags_prefix)
                ]
            )  # These are tags outside our namespace/prefix. Keep them.
            current_tags = utils.zabbix_tags2zac_tags(
                [
                    tag
                    for tag in zabbix_host["tags"]
                    if tag["tag"].startswith(self.config.tags_prefix)
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
                    "Tags (%s) not matching tags prefix ('%s') is configured on host '%s'. They will be ignored.",
                    ignored_tags,
                    self.config.tags_prefix,
                    zabbix_host["host"],
                )

            tags_to_remove = current_tags - db_tags
            tags_to_add = db_tags - current_tags
            tags = db_tags.union(other_zabbix_tags)
            if tags_to_remove or tags_to_add:
                if tags_to_remove:
                    logging.debug(
                        "Going to remove tags '%s' from host '%s'.",
                        tags_to_remove,
                        zabbix_host["host"],
                    )
                if tags_to_add:
                    logging.debug(
                        "Going to add tags '%s' to host '%s'.",
                        tags_to_add,
                        zabbix_host["host"],
                    )
                self.set_tags(zabbix_host, tags)

            if int(zabbix_host["inventory_mode"]) != 1:
                self.set_inventory_mode(zabbix_host, 1)

            if db_host.inventory:
                if zabbix_host["inventory"]:
                    changed_inventory = {
                        k: v
                        for k, v in db_host.inventory.items()
                        if db_host.inventory[k] != zabbix_host["inventory"].get(k, None)
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
    def clear_templates(self, templates: Dict[str, str], host: Dict[str, Any]) -> None:
        logging.debug("Clearing templates on host: '%s'", host["host"])
        if not self.config.dryrun:
            try:
                template_ids = [
                    {"templateid": template_id} for _, template_id in templates.items()
                ]
                self.api.host.update(
                    hostid=host["hostid"], templates_clear=template_ids
                )
            except pyzabbix.ZabbixAPIException as e:
                logging.error(
                    "Error when clearing templates on host '%s': %s",
                    host["host"],
                    e.args,
                )
        else:
            logging.debug("DRYRUN: Clearing templates on host: '%s'", host["host"])

    def set_templates(self, templates: Dict[str, str], host: Dict[str, Any]) -> None:
        if not self.config.dryrun:
            logging.debug("Setting templates on host: '%s'", host["host"])
            try:
                template_ids = [
                    {"templateid": template_id} for _, template_id in templates.items()
                ]
                self.api.host.update(hostid=host["hostid"], templates=template_ids)
            except pyzabbix.ZabbixAPIException as e:
                logging.error(
                    "Error when setting templates on host '%s': %s",
                    host["host"],
                    e.args,
                )
        else:
            logging.debug("DRYRUN: Setting templates on host: '%s'", host["host"])

    def do_update(self) -> None:
        managed_template_names = set(
            itertools.chain.from_iterable(self.property_template_map.values())
        )
        zabbix_templates = {}
        for zabbix_template in self.api.template.get(output=["host", "templateid"]):
            zabbix_templates[zabbix_template["host"]] = zabbix_template["templateid"]
        managed_template_names = managed_template_names.intersection(
            set(zabbix_templates.keys())
        )  # If the template isn't in zabbix we can't manage it
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT data FROM {self.db_hosts_table} WHERE data->>'enabled' = 'true'"
            )
            db_hosts = {
                t[0]["hostname"]: models.Host(**t[0]) for t in db_cursor.fetchall()
            }

        zabbix_hosts = {
            host["host"]: host
            for host in self.api.host.get(
                **{
                    "filter": {"status": 0, "flags": 0},
                    "output": ["hostid", "host"],
                    compat.param_host_get_groups(self.zabbix_version): [
                        "groupid",
                        "name",
                    ],
                    "selectParentTemplates": ["templateid", "host"],
                }
            )
        }

        for zabbix_hostname, zabbix_host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            if self.config.hostgroup_manual in [
                group["name"]
                for group in zabbix_host[compat.host_hostgroups(self.zabbix_version)]
            ]:
                logging.debug(
                    "Skipping manual host: '%s' (%s)",
                    zabbix_hostname,
                    zabbix_host["hostid"],
                )
                continue

            if zabbix_hostname not in db_hosts:
                logging.debug(
                    "Skipping host (It is not enabled in the database): '%s' (%s)",
                    zabbix_hostname,
                    zabbix_host["hostid"],
                )
                continue

            db_host = db_hosts[zabbix_hostname]

            synced_template_names = set()
            for _property in db_host.properties:
                if _property in self.property_template_map:
                    synced_template_names.update(self.property_template_map[_property])
            synced_template_names = synced_template_names.intersection(
                set(zabbix_templates.keys())
            )  # If the template isn't in zabbix we can't manage it

            host_templates = {}  # type: Dict[str, str]
            for zabbix_template in zabbix_host["parentTemplates"]:
                host_templates[zabbix_template["host"]] = zabbix_template["templateid"]

            old_host_templates = host_templates.copy()
            host_templates_to_remove = {}

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
                    self.clear_templates(host_templates_to_remove, zabbix_host)
                # TODO: Setting templates might not be necessary if we only removed templates. Consider refactor
                # TODO: Setting templates should not be performed if template clearing has failed (will lead to unlink without clear)
                self.set_templates(host_templates, zabbix_host)


class ZabbixHostgroupUpdater(ZabbixUpdater):
    def set_hostgroups(self, hostgroups: Dict[str, str], host: Dict[str, Any]) -> None:
        """Set host groups on a host given a mapping of host group names to IDs."""
        if not self.config.dryrun:
            logging.debug("Setting hostgroups on host: '%s'", host["host"])
            try:
                groups = [
                    {"groupid": hostgroup_id} for _, hostgroup_id in hostgroups.items()
                ]
                self.api.host.update(hostid=host["hostid"], groups=groups)
            except pyzabbix.ZabbixAPIException as e:
                logging.error(
                    "Error when setting hostgroups on host '%s': %s",
                    host["host"],
                    e.args,
                )
        else:
            logging.debug("DRYRUN: Setting hostgroups on host: '%s'", host["host"])

    def create_hostgroup(self, hostgroup_name: str) -> Optional[str]:
        if self.config.dryrun:
            logging.debug("DRYRUN: Creating hostgroup: '%s'", hostgroup_name)
            return None

        logging.debug("Creating hostgroup: '%s'", hostgroup_name)
        try:
            result = self.api.hostgroup.create(name=hostgroup_name)
            groupid = result["groupids"][0]
            logging.info("Created host group '%s' (%s)", hostgroup_name, groupid)
            return groupid
        except pyzabbix.ZabbixAPIException as e:
            logging.error(
                "Error when creating hostgroups '%s': %s", hostgroup_name, e.args
            )
            return None

    def create_extra_hostgroups(
        self, existing_hostgroups: List[Dict[str, str]]
    ) -> None:
        """Creates additonal host groups based on the prefixes specified
        in the config file. These host groups are not assigned hosts by ZAC."""
        hostgroup_names = set(h["name"] for h in existing_hostgroups)

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
            result = self.api.templategroup.create(name=templategroup_name)
            groupid = result["groupids"][0]
            logging.info(
                "Created template group '%s' (%s)", templategroup_name, groupid
            )
            return groupid
        except pyzabbix.ZabbixAPIException as e:
            logging.error(
                "Error when creating template group '%s': %s",
                templategroup_name,
                e.args,
            )
            return None

    def create_templategroups(self, existing_hostgroups: List[Dict[str, str]]) -> None:
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
                "Zabbix version is %s. Creating template groups.", self.zabbix_version
            )
            self._create_templategroups(tgroups)
        else:
            logging.debug(
                "Zabbix version is %s. Creating template groups as host groups.",
                self.zabbix_version,
            )
            self._create_templategroups_pre_62_compat(tgroups, existing_hostgroups)

    def _create_templategroups(self, tgroups: Set[str]) -> None:
        """Create the given template groups if they don't exist.

        Args:
            tgroups: A set of template group names to create.
        """
        res = self.api.templategroup.get(output=["name", "groupid"])
        existing_tgroups = set(tg["name"] for tg in res)
        for tgroup in tgroups:
            if tgroup in existing_tgroups:
                continue
            self.create_templategroup(tgroup)

    def _create_templategroups_pre_62_compat(
        self, tgroups: Set[str], existing_hostgroups: List[Dict[str, str]]
    ) -> None:
        """Compatibility method for creating template groups on Zabbix <6.2.

        Because template groups do not exist in <6.2, we instead create
        host groups with the given names.

        Args:
            tgroups: A set of host group names to create.
        """
        existing_hgroup_names = set(h["name"] for h in existing_hostgroups)
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

        existing_hostgroups = self.api.hostgroup.get(output=["name", "groupid"])

        # Create extra host groups if necessary
        if self.config.extra_siteadmin_hostgroup_prefixes:
            self.create_extra_hostgroups(existing_hostgroups)

        # Create template groups if enabled
        if self.config.create_templategroups:
            self.create_templategroups(existing_hostgroups)

        zabbix_hostgroups = {}  # type: Dict[str, str]
        for zabbix_hostgroup in existing_hostgroups:
            zabbix_hostgroups[zabbix_hostgroup["name"]] = str(
                zabbix_hostgroup["groupid"]
            )
            if zabbix_hostgroup["name"].startswith(self.config.hostgroup_source_prefix):
                managed_hostgroup_names.add(zabbix_hostgroup["name"])
            if zabbix_hostgroup["name"].startswith(
                self.config.hostgroup_importance_prefix
            ):
                managed_hostgroup_names.add(zabbix_hostgroup["name"])
        managed_hostgroup_names.update([self.config.hostgroup_all])

        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT data FROM {self.db_hosts_table} WHERE data->>'enabled' = 'true'"
            )
            db_hosts = {
                t[0]["hostname"]: models.Host(**t[0]) for t in db_cursor.fetchall()
            }
        zabbix_hosts = {
            host["host"]: host
            for host in self.api.host.get(
                **{
                    "filter": {"status": 0, "flags": 0},
                    "output": ["hostid", "host"],
                    compat.param_host_get_groups(self.zabbix_version): [
                        "groupid",
                        "name",
                    ],
                    "selectParentTemplates": ["templateid", "host"],
                }
            )
        }

        for zabbix_hostname, zabbix_host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            if self.config.hostgroup_manual in [
                group["name"]
                for group in zabbix_host[compat.host_hostgroups(self.zabbix_version)]
            ]:
                logging.debug(
                    "Skipping manual host: '%s' (%s)",
                    zabbix_hostname,
                    zabbix_host["hostid"],
                )
                continue

            if zabbix_hostname not in db_hosts:
                logging.debug(
                    "Skipping host (It is not enabled in the database): '%s' (%s)",
                    zabbix_hostname,
                    zabbix_host["hostid"],
                )
                continue

            db_host = db_hosts[zabbix_hostname]

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

            host_hostgroups = {}  # type: Dict[str, str]
            for zabbix_hostgroup in zabbix_host[
                compat.host_hostgroups(self.zabbix_version)
            ]:
                host_hostgroups[zabbix_hostgroup["name"]] = zabbix_hostgroup["groupid"]

            old_host_hostgroups = host_hostgroups.copy()

            for hostgroup_name in list(host_hostgroups.keys()):
                # TODO: Here lies a bug due to managed_hostgroup_names not being properly updated above?
                if (
                    hostgroup_name in managed_hostgroup_names
                    and hostgroup_name not in synced_hostgroup_names
                ):
                    logging.debug(
                        "Going to remove hostgroup '%s' from host '%s'.",
                        hostgroup_name,
                        zabbix_hostname,
                    )
                    del host_hostgroups[hostgroup_name]
            for hostgroup_name in synced_hostgroup_names:
                if hostgroup_name not in host_hostgroups.keys():
                    logging.debug(
                        "Going to add hostgroup '%s' to host '%s'.",
                        hostgroup_name,
                        zabbix_hostname,
                    )
                    zabbix_hostgroup_id = zabbix_hostgroups.get(hostgroup_name, None)
                    if not zabbix_hostgroup_id:
                        # The hostgroup doesn't exist. We need to create it.
                        zabbix_hostgroup_id = self.create_hostgroup(hostgroup_name)
                    if zabbix_hostgroup_id:
                        host_hostgroups[hostgroup_name] = zabbix_hostgroup_id

            if host_hostgroups != old_host_hostgroups:
                logging.info(
                    "Updating hostgroups on host '%s'. Old: %s. New: %s",
                    zabbix_hostname,
                    ", ".join(old_host_hostgroups.keys()),
                    ", ".join(host_hostgroups.keys()),
                )
                self.set_hostgroups(host_hostgroups, zabbix_host)
