import multiprocessing
import logging
import datetime
import os.path
import time
import sys
import signal
import itertools
import queue

import pymongo
import pyzabbix

from . import utils

class SourceCollectorProcess(multiprocessing.Process):
    def __init__(self, name, module, update_interval, source_hosts_queue, stop_event):
        super().__init__() 
        self.name = name
        self.module = module
        self.update_interval = update_interval
        self.source_hosts_queue = source_hosts_queue
        self.stop_event = stop_event

        self.next_update = None

    def run(self):
        logging.info("Process starting")

        while not self.stop_event.is_set():
            if self.next_update and self.next_update > datetime.datetime.now():
                #logging.debug(f"Waiting for next update {self.next_update.isoformat()}")
                time.sleep(1)
                continue

            self.next_update = datetime.datetime.now() + datetime.timedelta(seconds=self.update_interval)
            
            start_time = time.time()

            try:
                hosts = self.module.collect()
                assert type(hosts) is list, "Collect module did not return a list"
            except (AssertionError, Exception) as e:
                logging.warning(f"Error when collecting hosts: {str(e)}")
                continue

            valid_hosts = []
            for host in hosts:
                try:
                    host["source"] = self.name
                    utils.validate_host(host)
                    valid_hosts.append(host)
                except AssertionError as e:
                    if "hostname" in host:
                        logging.error(f"Host <{host['hostname']}> is invalid: {str(e)}")
                    else:
                        logging.error(f"Host object is invalid: {str(e)}")

            source_hosts = {
                "source": self.name,
                "hosts": valid_hosts,
            }

            self.source_hosts_queue.put(source_hosts)

            logging.info(f"Collected hosts ({len(valid_hosts)}) from source <{self.name}> in {time.time() - start_time:.2f}s. Next update {self.next_update.isoformat()}")

        self.source_hosts_queue.cancel_join_thread()  # Don't wait for empty queue
        logging.info("Process exiting")

class SourceHandlerProcess(multiprocessing.Process):
    def __init__(self, name, stop_event, db_uri, source_hosts_queues):
        super().__init__() 
        self.name = name
        self.stop_event = stop_event

        self.db_uri = db_uri
        self.source_hosts_queues = source_hosts_queues

    def run(self):
        logging.info("Process starting")

        try:
            self.mongo_client = pymongo.MongoClient(self.db_uri)
            self.mongo_client.admin.command('ismaster')  # Test connection
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error("Unable to connect to database. Process exiting with error")
            sys.exit(1)
        
        self.db = self.mongo_client.get_default_database()
        self.mongo_collection_hosts_source = self.db["hosts_source"]

        while not self.stop_event.is_set():
            for source_hosts_queue in self.source_hosts_queues:
                try:
                    source_hosts = source_hosts_queue.get_nowait()
                except queue.Empty:
                    continue
                
                self.handle_source_hosts(source_hosts)
            
            time.sleep(1)

        logging.info("Process exiting")

    @utils.handle_database_error
    def handle_source_hosts(self, source_hosts):
        source = source_hosts["source"]
        hosts = source_hosts["hosts"]
        
        start_time = time.time()
        equal_hosts, replaced_hosts, inserted_hosts, removed_hosts = (0, 0, 0, 0)

        source_hostnames = [host["hostname"] for host in hosts]
        current_hostnames = self.mongo_collection_hosts_source.distinct("hostname", {"source": source})

        removed_hostnames = set(current_hostnames) - set(source_hostnames)
        for removed_hostname in removed_hostnames:
            current_hostnames = self.mongo_collection_hosts_source.delete_one({"hostname": removed_hostname, "source": source})
            removed_hosts += 1

        for host in hosts:
            mongo_filter = {
                "hostname": host["hostname"],
                "source": source
            }
            current_host = self.mongo_collection_hosts_source.find_one(mongo_filter, projection={'_id': False})
            
            if current_host:
                if current_host == host:
                    equal_hosts += 1
                else:
                    #logging.debug(f"Replaced host <{host['hostname']}> from source <{source}>")
                    self.mongo_collection_hosts_source.replace_one(mongo_filter, host)
                    replaced_hosts += 1
            else:
                #logging.debug(f"Inserted host <{host['hostname']}> from source <{source}>")
                self.mongo_collection_hosts_source.insert_one(host)
                inserted_hosts += 1

        logging.info(f"Handled hosts from source <{source}> in {time.time() - start_time:.2f}s. Equal hosts: {equal_hosts}, replaced hosts: {replaced_hosts}, inserted hosts: {inserted_hosts}, removed hosts: {removed_hosts}")

class SourceMergerProcess(multiprocessing.Process):
    def __init__(self, name, stop_event, db_uri):
        super().__init__() 
        self.name = name
        self.stop_event = stop_event

        self.db_uri = db_uri

        self.update_interval = 60
        self.next_update = None

    def run(self):
        logging.info("Process starting")

        self.mongo_client = pymongo.MongoClient(self.db_uri)

        try:
            self.mongo_client.admin.command('ismaster')  # Test connection
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error("Unable to connect to database. Process exiting with error")
            sys.exit(1)
        
        self.mongo_db = self.mongo_client.get_default_database()
        self.mongo_collection_hosts_source = self.mongo_db["hosts_source"]
        self.mongo_collection_hosts = self.mongo_db["hosts"]

        while not self.stop_event.is_set():
            if self.next_update and self.next_update > datetime.datetime.now():
                #logging.debug(f"Waiting for next update {self.next_update.isoformat()}")
                time.sleep(1)
                continue

            self.next_update = datetime.datetime.now() + datetime.timedelta(seconds=self.update_interval)

            self.merge_sources()

            logging.info(f"Merge done. Next update {self.next_update.isoformat()}")

        self.mongo_client.close()

        logging.info("Process exiting")

    @utils.handle_database_error
    def merge_hosts(self, hostname):
        hosts = list(self.mongo_collection_hosts_source.find({"hostname": hostname}, projection={'_id': False}))

        if len(hosts) == 0:
            # Host not found. TODO: Raise error?
            return None
        else:
            merged_host = {
                "enabled": any([host["enabled"] for host in hosts]),
                "hostname": hostname,
                "importance": min([host.get("importance", 6) for host in hosts]),
                "interfaces": None, # TODO
                "inventory": None, # TODO
                "macros": None, # TODO
                "roles": sorted(list(set(itertools.chain.from_iterable([host["roles"] for host in hosts if "roles" in host])))),
                "siteadmins": sorted(list(set(itertools.chain.from_iterable([host["siteadmins"] for host in hosts if "siteadmins" in host])))),
                "sources": sorted(list(set([host["source"] for host in hosts if "source" in host])))
            }
            return merged_host

    @utils.handle_database_error
    def merge_sources(self):
        start_time = time.time()
        equal_hosts, replaced_hosts, inserted_hosts, removed_hosts = (0, 0, 0, 0)

        source_hostnames = self.mongo_collection_hosts_source.distinct("hostname")
        current_hostnames = self.mongo_collection_hosts.distinct("hostname")

        removed_hostnames = set(current_hostnames) - set(source_hostnames)
        for removed_hostname in removed_hostnames:
            current_hostnames = self.mongo_collection_hosts.delete_one({"hostname": removed_hostname})
            removed_hosts += 1
        
        for hostname in source_hostnames:
            host = self.merge_hosts(hostname)
            if not host:
                # TODO: Raise error? How to handle? Handle inside merge_hosts?
                continue

            # TODO: Pass host through modifiers here

            current_host = self.mongo_collection_hosts.find_one({"hostname": hostname}, projection={'_id': False})
            
            if current_host:
                if current_host == host:
                    equal_hosts += 1
                else:
                    #logging.debug(f"Replaced host <{host['hostname']}> from source <{source}>")
                    self.mongo_collection_hosts.replace_one({"hostname": hostname}, host)
                    replaced_hosts += 1
            else:
                #logging.debug(f"Inserted host <{host['hostname']}> from source <{source}>")
                self.mongo_collection_hosts.insert_one(host)
                inserted_hosts += 1

        logging.info(f"Merged sources in {time.time() - start_time:.2f}s. Equal hosts: {equal_hosts}, replaced hosts: {replaced_hosts}, inserted hosts: {inserted_hosts}, removed hosts: {removed_hosts}")

class ZabbixUpdater(multiprocessing.Process):
    def __init__(self, name, stop_event, map_dir, db_uri, zabbix_url, zabbix_username, zabbix_password):
        super().__init__()
        self.name = name
        self.stop_event = stop_event

        self.map_dir = map_dir
        self.db_uri = db_uri
        self.zabbix_url = zabbix_url
        self.zabbix_username = zabbix_username
        self.zabbix_password = zabbix_password

        self.update_interval = 60
        self.next_update = None

        pyzabbix_logger = logging.getLogger("pyzabbix")
        pyzabbix_logger.setLevel(logging.ERROR)

        self.api = pyzabbix.ZabbixAPI(zabbix_url)

        self.role_template_map = utils.read_map_file(os.path.join(map_dir, "role_template_map.txt"))
        self.role_hostgroup_map = utils.read_map_file(os.path.join(map_dir, "role_hostgroup_map.txt"))
        self.siteadmin_hostgroup_map = utils.read_map_file(os.path.join(map_dir, "siteadmin_hostgroup_map.txt"))

    def run(self):
        logging.info("Process starting")

        try:
            self.api.login(self.zabbix_username, self.zabbix_password)
        except pyzabbix.ZabbixAPIException as e:
            logging.error("Unable to login to Zabbix API: %s", str(e))
            sys.exit(1)

        self.mongo_client = pymongo.MongoClient(self.db_uri)

        try:
            self.mongo_client.admin.command('ismaster')  # Test connection
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error("Unable to connect to database. Process exiting with error")
            sys.exit(1)

        self.mongo_db = self.mongo_client.get_default_database()
        self.mongo_collection_hosts = self.mongo_db["hosts"]

        while not self.stop_event.is_set():
            if self.next_update and self.next_update > datetime.datetime.now():
                #logging.debug(f"Waiting for next update {self.next_update.isoformat()}")
                time.sleep(1)
                continue

            self.next_update = datetime.datetime.now() + datetime.timedelta(seconds=self.update_interval)

            self.work()

            logging.info(f"Zabbix update done. Next update {self.next_update.isoformat()}")

        self.mongo_client.close()

        logging.info("Process exiting")

    def work(self):
        pass

class ZabbixHostUpdater(ZabbixUpdater):

    def disable_host(self, zabbix_host, dryrun=True):
        if not dryrun:
            manual_hostgroup_id = self.api.hostgroup.get(filter={"name": "All-manual-hosts"})[0]["groupid"]
            self.api.host.update(hostid=zabbix_host["hostid"], status=1, templates=[], groups=[{"groupid": manual_hostgroup_id}])
            logging.info("Disabling host: '{}' ({})".format(zabbix_host["host"], zabbix_host["hostid"]))
        else:
            logging.info("DRYRUN: Disabling host: '{}' ({})".format(zabbix_host["host"], zabbix_host["hostid"]))

    def enable_host(self, hostname, dryrun=True):
        """
        . create / enable
        . add templates
        . add groups
        """
        if not dryrun:
            hosts = self.api.host.get(filter={"name": hostname})
            if hosts:
                host = hosts[0]
                self.api.host.update(hostid=host["hostid"], status=0)
                logging.info("Enabling old host: '{}' ({})".format(host["hostname"], host["hostid"]))
            else:
                hostgroup_id = self.api.hostgroup.get(filter={"name": "All-hosts"})[0]["groupid"]
                interface = {
                    "dns": hostname,
                    "ip": "",
                    "useip": 0,
                    "type": 1,
                    "port": 10050,
                    "main": 1
                }
                result = self.api.host.create(host=hostname, status=0, groups=[{"groupid": hostgroup_id}], interfaces=[interface])
                logging.info("Enabling new host: '{}' ({})".format(host["hostname"], result["hostids"][0]))
        else:
            logging.info("DRYRUN: Enabling host: '{}'".format(hostname))

    @utils.handle_database_error
    def work(self):
        db_hosts = list(self.mongo_collection_hosts.find({"enabled": True}, projection={'_id': False}))
        # status:0 = monitored, flags:0 = non-discovered host
        zabbix_hosts = self.api.host.get(filter={"status": 0, "flags": 0}, output=["hostid", "host", "status", "flags"], selectGroups=["groupid", "name"], selectParentTemplates=["templateid", "host"])
        zabbix_managed_hosts = []
        zabbix_manual_hosts = []

        for host in zabbix_hosts:
            hostgroup_names = [group["name"] for group in host["groups"]]
            if "All-manual-hosts" in hostgroup_names:
                zabbix_manual_hosts.append(host)
            else:
                zabbix_managed_hosts.append(host)


        db_hostnames = set([host["hostname"] for host in db_hosts])
        zabbix_hostnames = set([host["host"] for host in zabbix_managed_hosts])

        hostnames_to_remove = list(zabbix_hostnames - db_hostnames)
        hostnames_to_add = list(db_hostnames - zabbix_hostnames)
        hostnames_in_both = list(db_hostnames.intersection(zabbix_hostnames))

        logging.info("Manual in zabbix: {}".format(len(zabbix_manual_hosts)))
        logging.info("Only in zabbix: {}".format(len(hostnames_to_remove)))
        logging.info("Only in zabbix: {}".format(" ".join(hostnames_to_remove[:10])))
        logging.info("Only in db: {}".format(len(hostnames_to_add)))
        logging.info("Only in db: {}".format(" ".join(hostnames_to_add[:10])))
        logging.info("In both: {}".format(len(hostnames_in_both)))

        for hostname in hostnames_to_remove:
            zabbix_host = [host for host in zabbix_managed_hosts if hostname == host["host"]][0]
            self.disable_host(zabbix_host)

        for hostname in hostnames_to_add:
            self.enable_host(hostname)

class ProcessTerminator():
    def __init__(self, stop_event):
        self.stop_event = stop_event

    def __enter__(self):
        self.old_sigint_handler = signal.signal(signal.SIGINT, self._handler)
        self.old_sigterm_handler = signal.signal(signal.SIGTERM, self._handler)

    def __exit__(self, *args):
        signal.signal(signal.SIGINT, self.old_sigint_handler)
        signal.signal(signal.SIGTERM, self.old_sigterm_handler)

    def _handler(self, signum, frame):
        logging.info(f"Received signal: {signal.Signals(signum).name}")  #  https://github.com/PyCQA/pylint/issues/2804 pylint: disable=E1101
        self.stop_event.set()
