import multiprocessing
import logging
import datetime
import json
import os.path
import random
import re
import time
import sys
import signal
import itertools
import queue

import psycopg2
import pyzabbix

from . import utils


class BaseProcess(multiprocessing.Process):
    def __init__(self, sleep_interval=1):
        super().__init__()
        self.sleep_interval = sleep_interval

        self.stop_event = multiprocessing.Event()

    def run(self):
        logging.info("Process starting")

        with SignalHandler(self.stop_event):
            while not self.stop_event.is_set():
                self.work()
                time.sleep(self.sleep_interval)

        logging.info("Process exiting")

    def work(self):
        pass


class SignalHandler():
    def __init__(self, event):
        self.event = event

    def __enter__(self):
        self.old_sigint_handler = signal.signal(signal.SIGINT, self._handler)
        self.old_sigterm_handler = signal.signal(signal.SIGTERM, self._handler)

    def __exit__(self, *args):
        signal.signal(signal.SIGINT, self.old_sigint_handler)
        signal.signal(signal.SIGTERM, self.old_sigterm_handler)

    def _handler(self, signum, frame):
        logging.info("Received signal: %s", signal.Signals(signum).name)
        self.event.set()


class SourceCollectorProcess(BaseProcess):
    def __init__(self, name, module, config, source_hosts_queue):
        super().__init__()
        self.name = name
        self.module = module
        self.config = config
        self.source_hosts_queue = source_hosts_queue
        self.source_hosts_queue.cancel_join_thread()  # Don't wait for empty queue when exiting

        self.update_interval = int(self.config["update_interval"])
        self.next_update = None

    def work(self):
        if self.next_update and self.next_update > datetime.datetime.now():
            # logging.debug(f"Waiting for next update {self.next_update.isoformat()}")
            return

        self.next_update = datetime.datetime.now() + datetime.timedelta(seconds=self.update_interval)

        start_time = time.time()

        try:
            hosts = self.module.collect(**self.config)
            assert isinstance(hosts, list), "Collect module did not return a list"
        except (AssertionError, Exception) as e:
            logging.warning("Error when collecting hosts: %s", str(e))
            # TODO: Do more? Die?
            return

        valid_hosts = []
        for host in hosts:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            try:
                host["source"] = self.name
                utils.validate_host(host)
                valid_hosts.append(host)
            except AssertionError as e:
                if "hostname" in host:
                    logging.error("Host <%s> is invalid: %s", host['hostname'], str(e))
                else:
                    logging.error("Host object is invalid: %s", str(e))

        source_hosts = {
            "source": self.name,
            "hosts": valid_hosts,
        }

        self.source_hosts_queue.put(source_hosts)

        logging.info(f"Collected hosts ({len(valid_hosts)}) from source <{self.name}> in {time.time() - start_time:.2f}s. Next update {self.next_update.isoformat()}")


class SourceHandlerProcess(BaseProcess):
    def __init__(self, name, db_uri, source_hosts_queues):
        super().__init__()
        self.name = name

        self.db_uri = db_uri
        self.db_source_table = "hosts_source"

        try:
            self.db_connection = psycopg2.connect(self.db_uri)
            # TODO: Test connection? Cursor?
        except psycopg2.OperationalError as e:
            logging.error("Unable to connect to database.")
            raise e

        self.source_hosts_queues = source_hosts_queues
        for source_hosts_queue in self.source_hosts_queues:
            source_hosts_queue.cancel_join_thread()  # Don't wait for empty queue when exiting

    def work(self):
        for source_hosts_queue in self.source_hosts_queues:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            try:
                source_hosts = source_hosts_queue.get_nowait()
            except queue.Empty:
                continue

            logging.debug("Handling source from queue")
            self.handle_source_hosts(source_hosts)

    def handle_source_hosts(self, source_hosts):
        source = source_hosts["source"]
        hosts = source_hosts["hosts"]

        start_time = time.time()
        equal_hosts, replaced_hosts, inserted_hosts, removed_hosts = (0, 0, 0, 0)

        source_hostnames = {host["hostname"] for host in hosts}
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(f"SELECT DISTINCT data->>'hostname' FROM {self.db_source_table} WHERE data->>'source' = %s", [source])
            current_hostnames = {t[0] for t in db_cursor.fetchall()}

        removed_hostnames = current_hostnames - source_hostnames
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            for removed_hostname in removed_hostnames:
                db_cursor.execute(f"DELETE FROM {self.db_source_table} WHERE data->>'hostname' = %s AND data->>'source' = %s", [removed_hostname, source])
                removed_hosts += 1

        for host in hosts:
            with self.db_connection, self.db_connection.cursor() as db_cursor:
                db_cursor.execute(f"SELECT data FROM {self.db_source_table} WHERE data->>'hostname' = %s AND data->>'source' = %s", [host["hostname"], source])
                result = db_cursor.fetchall()
                current_host = result[0][0] if result else None

            if current_host:
                if current_host == host:
                    equal_hosts += 1
                else:
                    # logging.debug(f"Replaced host <{host['hostname']}> from source <{source}>")
                    with self.db_connection, self.db_connection.cursor() as db_cursor:
                        db_cursor.execute(f"UPDATE {self.db_source_table} SET data = %s WHERE data->>'hostname' = %s AND data->>'source' = %s", [json.dumps(host), host["hostname"], source])
                    replaced_hosts += 1
            else:
                # logging.debug(f"Inserted host <{host['hostname']}> from source <{source}>")
                with self.db_connection, self.db_connection.cursor() as db_cursor:
                    db_cursor.execute(f"INSERT INTO {self.db_source_table} (data) VALUES (%s)", [json.dumps(host)])
                inserted_hosts += 1

        logging.info(f"Handled hosts from source <{source}> in {time.time() - start_time:.2f}s. Equal hosts: {equal_hosts}, replaced hosts: {replaced_hosts}, inserted hosts: {inserted_hosts}, removed hosts: {removed_hosts}")


class SourceMergerProcess(BaseProcess):
    def __init__(self, name, db_uri):
        super().__init__()
        self.name = name

        self.db_uri = db_uri
        self.db_source_table = "hosts_source"
        self.db_hosts_table = "hosts"

        try:
            self.db_connection = psycopg2.connect(self.db_uri)
            # TODO: Test connection? Cursor?
        except psycopg2.OperationalError:
            logging.error("Unable to connect to database. Process exiting with error")
            sys.exit(1)

        self.update_interval = 60
        self.next_update = None

    def work(self):
        if self.next_update and self.next_update > datetime.datetime.now():
            # logging.debug(f"Waiting for next update {self.next_update.isoformat()}")
            return

        self.next_update = datetime.datetime.now() + datetime.timedelta(seconds=self.update_interval)

        logging.info("Merge starting")
        self.merge_sources()
        logging.info("Merge done. Next update %s", self.next_update.isoformat())

        if self.next_update < datetime.datetime.now():
            logging.warning("Next update is in the past. Interval too short? Lagging behind? Next update: %s", self.next_update.isoformat())

    def merge_hosts(self, hostname):
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(f"SELECT data FROM {self.db_source_table} WHERE data->>'hostname' = %s", [hostname])
            hosts = [t[0] for t in db_cursor.fetchall()]

        if len(hosts) == 0:
            # Host not found. TODO: Raise error?
            return None

        merged_host = {
            "enabled": any([host["enabled"] for host in hosts]),
            "hostname": hostname,
            "importance": min([host.get("importance", 6) for host in hosts]),
            "interfaces": None,  # TODO
            "inventory": None,  # TODO
            "macros": None,  # TODO
            "properties": sorted(list(set(itertools.chain.from_iterable([host["properties"] for host in hosts if "properties" in host])))),
            "siteadmins": sorted(list(set(itertools.chain.from_iterable([host["siteadmins"] for host in hosts if "siteadmins" in host])))),
            "sources": sorted(list({host["source"] for host in hosts if "source" in host}))
        }
        proxy_patterns = list(set([host["proxy_pattern"] for host in hosts if "proxy_pattern" in host]))
        if proxy_patterns:
            # TODO: Refactor? Selecting a random pattern might lead to proxy flopping if "bad" patterns are provided.
            merged_host["proxy_pattern"] = random.choice(proxy_patterns)
        else:
            merged_host["proxy_pattern"] = None

        return merged_host

    def merge_sources(self):
        start_time = time.time()
        equal_hosts, replaced_hosts, inserted_hosts, removed_hosts = (0, 0, 0, 0)

        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(f"SELECT DISTINCT data->>'hostname' FROM {self.db_source_table}")
            source_hostnames = {t[0] for t in db_cursor.fetchall()}
            db_cursor.execute(f"SELECT DISTINCT data->>'hostname' FROM {self.db_hosts_table}")
            current_hostnames = {t[0] for t in db_cursor.fetchall()}

        removed_hostnames = current_hostnames - source_hostnames
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            for removed_hostname in removed_hostnames:
                if self.stop_event.is_set():
                    logging.debug("Told to stop. Breaking")
                    break
                db_cursor.execute(f"DELETE FROM {self.db_hosts_table} WHERE data->>'hostname' = %s", [removed_hostname])
                removed_hosts += 1

        for hostname in source_hostnames:
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            host = self.merge_hosts(hostname)
            if not host:
                # TODO: Raise error? How to handle? Handle inside merge_hosts?
                continue

            # TODO: Pass host through modifiers here

            with self.db_connection, self.db_connection.cursor() as db_cursor:
                db_cursor.execute(f"SELECT data FROM {self.db_hosts_table} WHERE data->>'hostname' = %s", [hostname])
                result = db_cursor.fetchall()
                current_host = result[0][0] if result else None

            if current_host:
                if current_host == host:
                    equal_hosts += 1
                else:
                    # logging.debug(f"Replaced host <{host['hostname']}> from source <{source}>")
                    with self.db_connection, self.db_connection.cursor() as db_cursor:
                        db_cursor.execute(f"UPDATE {self.db_hosts_table} SET data = %s WHERE data->>'hostname' = %s", [json.dumps(host), hostname])
                        replaced_hosts += 1
            else:
                # logging.debug(f"Inserted host <{host['hostname']}> from source <{source}>")
                with self.db_connection, self.db_connection.cursor() as db_cursor:
                    db_cursor.execute(f"INSERT INTO {self.db_hosts_table} (data) VALUES (%s)", [json.dumps(host)])
                    inserted_hosts += 1

        logging.info(f"Merged sources in {time.time() - start_time:.2f}s. Equal hosts: {equal_hosts}, replaced hosts: {replaced_hosts}, inserted hosts: {inserted_hosts}, removed hosts: {removed_hosts}")


class ZabbixUpdater(BaseProcess):
    def __init__(self, name, db_uri, zabbix_config):
        super().__init__()
        self.name = name

        self.db_uri = db_uri
        self.db_hosts_table = "hosts"

        try:
            self.db_connection = psycopg2.connect(self.db_uri)
            # TODO: Test connection? Cursor?
        except psycopg2.OperationalError as e:
            logging.error("Unable to connect to database. Process exiting with error")
            raise e

        self.map_dir = zabbix_config["map_dir"]
        self.zabbix_url = zabbix_config["url"]
        self.zabbix_username = zabbix_config["username"]
        self.zabbix_password = zabbix_config["password"]
        self.dryrun = zabbix_config["dryrun"]
        self.failsafe = zabbix_config["failsafe"]

        self.update_interval = 60
        self.next_update = None

        pyzabbix_logger = logging.getLogger("pyzabbix")
        pyzabbix_logger.setLevel(logging.ERROR)

        self.api = pyzabbix.ZabbixAPI(self.zabbix_url)
        try:
            self.api.login(self.zabbix_username, self.zabbix_password)
        except pyzabbix.ZabbixAPIException as e:
            logging.error("Unable to login to Zabbix API: %s", str(e))
            raise e

        self.property_template_map = utils.read_map_file(os.path.join(self.map_dir, "property_template_map.txt"))
        self.property_hostgroup_map = utils.read_map_file(os.path.join(self.map_dir, "property_hostgroup_map.txt"))
        self.siteadmin_hostgroup_map = utils.read_map_file(os.path.join(self.map_dir, "siteadmin_hostgroup_map.txt"))

    def work(self):
        if self.next_update and self.next_update > datetime.datetime.now():
            # logging.debug(f"Waiting for next update {self.next_update.isoformat()}")
            return

        self.next_update = datetime.datetime.now() + datetime.timedelta(seconds=self.update_interval)
        self.do_update()
        logging.info("Zabbix update done. Next update %s", self.next_update.isoformat())

        if self.next_update < datetime.datetime.now():
            logging.warning("Next update is in the past. Interval too short? Lagging behind? Next update: %s", self.next_update.isoformat())

    def do_update(self):
        pass


class ZabbixHostUpdater(ZabbixUpdater):

    def disable_host(self, zabbix_host):
        if not self.dryrun:
            try:
                disabled_hostgroup_id = self.api.hostgroup.get(filter={"name": "All-auto-disabled-hosts"})[0]["groupid"]
                self.api.host.update(hostid=zabbix_host["hostid"], status=1, templates=[], groups=[{"groupid": disabled_hostgroup_id}])
                logging.info("Disabling host: '%s' (%s)", zabbix_host["host"], zabbix_host["hostid"])
            except pyzabbix.ZabbixAPIException as e:
                logging.error("Error when disabling host '%s' (%s): %s", zabbix_host["host"], zabbix_host["hostid"], e.args)
        else:
            logging.info("DRYRUN: Disabling host: '%s' (%s)", zabbix_host["host"], zabbix_host["hostid"])

    def enable_host(self, db_host):
        # TODO: Set correct proxy when enabling
        hostname = db_host["hostname"]
        if not self.dryrun:
            try:
                hostgroup_id = self.api.hostgroup.get(filter={"name": "All-hosts"})[0]["groupid"]

                hosts = self.api.host.get(filter={"name": hostname})
                if hosts:
                    host = hosts[0]
                    self.api.host.update(hostid=host["hostid"], status=0, groups=[{"groupid": hostgroup_id}])
                    logging.info("Enabling old host: '%s' (%s)", host["host"], host["hostid"])
                else:
                    interface = {
                        "dns": hostname,
                        "ip": "",
                        "useip": 0,
                        "type": 1,
                        "port": 10050,
                        "main": 1
                    }
                    result = self.api.host.create(host=hostname, status=0, groups=[{"groupid": hostgroup_id}], interfaces=[interface])
                    logging.info("Enabling new host: '%s' (%s)", hostname, result["hostids"][0])
            except pyzabbix.ZabbixAPIException as e:
                logging.error("Error when enabling/creating host '%s': %s", hostname, e.args)
        else:
            logging.info("DRYRUN: Enabling host: '%s'", hostname)

    def clear_proxy(self, zabbix_host):
        if not self.dryrun:
            self.api.host.update(hostid=zabbix_host["hostid"], proxy_hostid="0")
            logging.info("Clearing proxy on host: '%s' (%s)", zabbix_host["host"], zabbix_host["hostid"])
        else:
            logging.info("DRYRUN: Clearing proxy on host: '%s' (%s)", zabbix_host["host"], zabbix_host["hostid"])

    def set_proxy(self, zabbix_host, zabbix_proxy):
        if not self.dryrun:
            self.api.host.update(hostid=zabbix_host["hostid"], proxy_hostid=zabbix_proxy["proxyid"])
            logging.info("Setting proxy (%s) on host: '%s' (%s)", zabbix_proxy["host"], zabbix_host["host"], zabbix_host["hostid"])
        else:
            logging.info("DRYRUN: Setting proxy (%s) on host: '%s' (%s)", zabbix_proxy["host"], zabbix_host["host"], zabbix_host["hostid"])

    def do_update(self):
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(f"SELECT data FROM {self.db_hosts_table} WHERE data->>'enabled' = 'true'")
            db_hosts = {t[0]["hostname"]:t[0] for t in db_cursor.fetchall()}
        # status:0 = monitored, flags:0 = non-discovered host
        zabbix_hosts = {host["host"]:host for host in self.api.host.get(filter={"status": 0, "flags": 0}, output=["hostid", "host", "status", "flags", "proxy_hostid"], selectGroups=["groupid", "name"], selectParentTemplates=["templateid", "host"])}
        zabbix_proxies = {proxy["host"]:proxy for proxy in self.api.proxy.get(output=["proxyid", "host", "status"])}
        zabbix_managed_hosts = []
        zabbix_manual_hosts = []

        for hostname, host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break
            hostgroup_names = [group["name"] for group in host["groups"]]
            if "All-manual-hosts" in hostgroup_names:
                zabbix_manual_hosts.append(host)
            else:
                zabbix_managed_hosts.append(host)

        db_hostnames = {hostname for hostname in db_hosts.keys()}
        zabbix_managed_hostnames = {host["host"] for host in zabbix_managed_hosts}
        zabbix_manual_hostnames = {host["host"] for host in zabbix_manual_hosts}

        hostnames_to_remove = list(zabbix_managed_hostnames - db_hostnames - zabbix_manual_hostnames)
        hostnames_to_add = list(db_hostnames - zabbix_managed_hostnames - zabbix_manual_hostnames)
        hostnames_in_both = list(db_hostnames.intersection(zabbix_managed_hostnames) - zabbix_manual_hostnames)

        logging.debug("Manual in zabbix: %d", len(zabbix_manual_hostnames))
        logging.debug("Only in zabbix: %d", len(hostnames_to_remove))
        logging.debug("Only in zabbix: %s", " ".join(hostnames_to_remove[:10]))
        logging.debug("Only in db: %d", len(hostnames_to_add))
        logging.debug("Only in db: %s", " ".join(hostnames_to_add[:10]))
        logging.debug("In both: %d", len(hostnames_in_both))

        if len(hostnames_to_remove) > self.failsafe or len(hostnames_to_add) > self.failsafe:
            logging.warning("Too many hosts to change (failsafe=%d). Remove: %d, Add: %d. Aborting", self.failsafe, len(hostnames_to_remove), len(hostnames_to_add))
            return

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
            zabbix_proxy_id = zabbix_host["proxy_hostid"]
            zabbix_proxy = [proxy for proxy in zabbix_proxies.values() if proxy["proxyid"] == zabbix_proxy_id]
            current_zabbix_proxy = zabbix_proxy[0] if zabbix_proxy else None
            if db_host["proxy_pattern"]:
                possible_proxies = [proxy for proxy in zabbix_proxies.values() if re.match(db_host["proxy_pattern"], proxy["host"])]
                if not possible_proxies:
                    logging.error("Proxy pattern ('%s') for host, '%s' (%s), doesn't match any proxies.", db_host["proxy_pattern"], hostname, zabbix_host["hostid"])
                else:
                    new_proxy = random.choice(possible_proxies)
                    if current_zabbix_proxy and not re.match(db_host["proxy_pattern"], current_zabbix_proxy["host"]):
                        # Wrong proxy, set new
                        self.set_proxy(zabbix_host, new_proxy)
                    elif not current_zabbix_proxy:
                        # Missing proxy, set new
                        self.set_proxy(zabbix_host, new_proxy)
            elif not db_host["proxy_pattern"]:
                if current_zabbix_proxy:
                    # Should not have proxy, remove
                    self.clear_proxy(zabbix_host)


class ZabbixTemplateUpdater(ZabbixUpdater):

    def clear_templates(self, templates, host):
        logging.debug("Clearing templates on host: '%s'", host["host"])
        if not self.dryrun:
            try:
                templates = [{"templateid": template_id} for _, template_id in templates.items()]
                self.api.host.update(hostid=host["hostid"], templates_clear=templates)
            except pyzabbix.ZabbixAPIException as e:
                logging.error("Error when clearing templates on host '%s': %s", host["host"], e.args)

    def set_templates(self, templates, host):
        logging.debug("Setting templates on host: '%s'", host["host"])
        if not self.dryrun:
            try:
                templates = [{"templateid": template_id} for _, template_id in templates.items()]
                self.api.host.update(hostid=host["hostid"], templates=templates)
            except pyzabbix.ZabbixAPIException as e:
                logging.error("Error when setting templates on host '%s': %s", host["host"], e.args)

    def do_update(self):
        managed_template_names = set(itertools.chain.from_iterable(self.property_template_map.values()))
        zabbix_templates = {}
        for zabbix_template in self.api.template.get(output=["host", "templateid"]):
            zabbix_templates[zabbix_template["host"]] = zabbix_template["templateid"]
        managed_template_names = managed_template_names.intersection(set(zabbix_templates.keys()))  # If the template isn't in zabbix we can't manage it
        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(f"SELECT data FROM {self.db_hosts_table} WHERE data->>'enabled' = 'true'")
            db_hosts = {t[0]["hostname"]:t[0] for t in db_cursor.fetchall()}
        zabbix_hosts = {host["host"]:host for host in self.api.host.get(filter={"status": 0, "flags": 0}, output=["hostid", "host"], selectGroups=["groupid", "name"], selectParentTemplates=["templateid", "host"])}

        for zabbix_hostname, zabbix_host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            if "All-manual-hosts" in [group["name"] for group in zabbix_host["groups"]]:
                logging.debug("Skipping manual host: '%s' (%s)", zabbix_hostname, zabbix_host["hostid"])
                continue

            if zabbix_hostname not in db_hosts:
                logging.debug("Skipping host (It is not enabled in the database): '%s' (%s)", zabbix_hostname, zabbix_host["hostid"])
                continue

            db_host = db_hosts[zabbix_hostname]

            synced_template_names = set()
            for _property in db_host["properties"]:
                if _property in self.property_template_map:
                    synced_template_names.update(self.property_template_map[_property])
            synced_template_names = synced_template_names.intersection(set(zabbix_templates.keys()))  # If the template isn't in zabbix we can't manage it

            host_templates = {}
            for zabbix_template in zabbix_host["parentTemplates"]:
                host_templates[zabbix_template["host"]] = zabbix_template["templateid"]

            old_host_templates = host_templates.copy()
            host_templates_to_remove = {}

            for template_name in list(host_templates.keys()):
                if template_name in managed_template_names and template_name not in synced_template_names:
                    logging.debug("Going to remove template '%s' from host '%s'.", template_name, zabbix_hostname)
                    host_templates_to_remove[template_name] = host_templates[template_name]
                    del host_templates[template_name]
            for template_name in synced_template_names:
                if template_name not in host_templates.keys():
                    logging.debug("Going to add template '%s' to host '%s'.", template_name, zabbix_hostname)
                    host_templates[template_name] = zabbix_templates[template_name]

            if host_templates != old_host_templates:
                logging.info("Updating templates on host '%s'. Old: %s. New: %s", zabbix_hostname, ", ".join(old_host_templates.keys()), ", ".join(host_templates.keys()))
                if host_templates_to_remove:
                    self.clear_templates(host_templates_to_remove, zabbix_host)
                # TODO: Setting templates might not be necessary if we only removed templates. Consider refactor
                # TODO: Setting templates should not be performed if template clearing has failed (will lead to unlink without clear)
                self.set_templates(host_templates, zabbix_host)


class ZabbixHostgroupUpdater(ZabbixUpdater):

    def set_hostgroups(self, hostgroups, host):
        logging.debug("Setting hostgroups on host: '%s'", host["host"])
        if not self.dryrun:
            try:
                groups = [{"groupid": hostgroup_id} for _, hostgroup_id in hostgroups.items()]
                self.api.host.update(hostid=host["hostid"], groups=groups)
            except pyzabbix.ZabbixAPIException as e:
                logging.error("Error when setting hostgroups on host '%s': %s", host["host"], e.args)

    def create_hostgroup(self, hostgroup_name):
        if not self.dryrun:
            try:
                result = self.api.hostgroup.create(name=hostgroup_name)
                return result["groupids"][0]
            except pyzabbix.ZabbixAPIException as e:
                logging.error("Error when creating hostgroups '%s': %s", hostgroup_name, e.args)
        else:
            return "-1"

    def do_update(self):
        managed_hostgroup_names = set(itertools.chain.from_iterable(self.property_hostgroup_map.values()))
        managed_hostgroup_names.union(set(itertools.chain.from_iterable(self.siteadmin_hostgroup_map.values())))
        zabbix_hostgroups = {}
        for zabbix_hostgroup in self.api.hostgroup.get(output=["name", "groupid"]):
            zabbix_hostgroups[zabbix_hostgroup["name"]] = zabbix_hostgroup["groupid"]
            if zabbix_hostgroup["name"].startswith("Source-"):
                managed_hostgroup_names.add(zabbix_hostgroup["name"])
        managed_hostgroup_names.update(["All-hosts"])

        with self.db_connection, self.db_connection.cursor() as db_cursor:
            db_cursor.execute(f"SELECT data FROM {self.db_hosts_table} WHERE data->>'enabled' = 'true'")
            db_hosts = {t[0]["hostname"]:t[0] for t in db_cursor.fetchall()}
        zabbix_hosts = {host["host"]:host for host in self.api.host.get(filter={"status": 0, "flags": 0}, output=["hostid", "host"], selectGroups=["groupid", "name"], selectParentTemplates=["templateid", "host"])}

        for zabbix_hostname, zabbix_host in zabbix_hosts.items():
            if self.stop_event.is_set():
                logging.debug("Told to stop. Breaking")
                break

            if "All-manual-hosts" in [group["name"] for group in zabbix_host["groups"]]:
                logging.debug("Skipping manual host: '%s' (%s)", zabbix_hostname, zabbix_host["hostid"])
                continue

            if zabbix_hostname not in db_hosts:
                logging.debug("Skipping host (It is not enabled in the database): '%s' (%s)", zabbix_hostname, zabbix_host["hostid"])
                continue

            db_host = db_hosts[zabbix_hostname]

            synced_hostgroup_names = set(["All-hosts"])
            for _property in db_host["properties"]:
                if _property in self.property_hostgroup_map:
                    synced_hostgroup_names.update(self.property_hostgroup_map[_property])
            for siteadmin in db_host["siteadmins"]:
                if siteadmin in self.siteadmin_hostgroup_map:
                    synced_hostgroup_names.update(self.siteadmin_hostgroup_map[siteadmin])
            for source in db_host["sources"]:
                synced_hostgroup_names.add(f"Source-{source}")

            host_hostgroups = {}
            for zabbix_hostgroup in zabbix_host["groups"]:
                host_hostgroups[zabbix_hostgroup["name"]] = zabbix_hostgroup["groupid"]

            old_host_hostgroups = host_hostgroups.copy()

            for hostgroup_name in list(host_hostgroups.keys()):
                if hostgroup_name in managed_hostgroup_names and hostgroup_name not in synced_hostgroup_names:
                    logging.debug("Going to remove hostgroup '%s' from host '%s'.", hostgroup_name, zabbix_hostname)
                    del host_hostgroups[hostgroup_name]
            for hostgroup_name in synced_hostgroup_names:
                if hostgroup_name not in host_hostgroups.keys():
                    logging.debug("Going to add hostgroup '%s' to host '%s'.", hostgroup_name, zabbix_hostname)
                    zabbix_hostgroup_id = zabbix_hostgroups.get(hostgroup_name, None)
                    if not zabbix_hostgroup_id:
                        # The hostgroup doesn't exist. We need to create it.
                        zabbix_hostgroup_id = self.create_hostgroup(hostgroup_name)
                    host_hostgroups[hostgroup_name] = zabbix_hostgroup_id

            if host_hostgroups != old_host_hostgroups:
                logging.info("Updating hostgroups on host '%s'. Old: %s. New: %s", zabbix_hostname, ", ".join(old_host_hostgroups.keys()), ", ".join(host_hostgroups.keys()))
                self.set_hostgroups(host_hostgroups, zabbix_host)
