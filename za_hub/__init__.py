import configparser
import datetime
import importlib
import logging
import multiprocessing
import os
import os.path
import sys
import time

import multiprocessing_logging

from .__version__ import __version__
from . import processing


def get_source_collectors(config):
    source_collector_dir = config["za-hub"]["source_collector_dir"]
    sys.path.append(source_collector_dir)

    section_prefix = "source-collector-"
    source_collector_sections = [config_section for config_section in config.sections() if config_section.startswith(section_prefix)]

    source_collectors = []

    for source_collector_section in source_collector_sections:
        source_collector_name = source_collector_section[len(section_prefix):]

        try:
            module = importlib.import_module(source_collector_name)
        except ModuleNotFoundError:
            logging.error("Unable to find source collector named '{}' in '{}'".format(source_collector_name, source_collector_dir))
            continue

        source_collector = {
            "name": source_collector_name,
            "module": module,
            "update_interval": int(config[source_collector_section].get("update_interval", "3600"))
        }

        source_collectors.append(source_collector)

    return source_collectors


def get_config():
    cwd = os.getcwd()
    config_file = os.path.join(cwd, "config.ini")
    config = configparser.ConfigParser()
    config.read(config_file)

    return config


def main():
    config = get_config()

    logging.basicConfig(format='%(asctime)s %(levelname)s [%(processName)s %(process)d] [%(name)s] %(message)s', datefmt="%Y-%m-%dT%H:%M:%S%z", level=logging.DEBUG)
    multiprocessing_logging.install_mp_handler()
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    if config["za-hub"]["dryrun"] == "false":
        dryrun = False
    elif config["za-hub"]["dryrun"] == "true":
        dryrun = True
    else:
        raise Exception()

    logging.info(f"Main start ({os.getpid()}) version {__version__}")

    stop_event = multiprocessing.Event()
    processes = []

    source_hosts_queues = []
    source_collectors = get_source_collectors(config)
    for source_collector in source_collectors:
        source_hosts_queue = multiprocessing.Queue()
        process = processing.SourceCollectorProcess(source_collector["name"], source_collector["module"], source_collector["update_interval"], source_hosts_queue, stop_event)
        source_hosts_queues.append(source_hosts_queue)
        processes.append(process)
        process.start()

    process = processing.SourceHandlerProcess("source-handler", stop_event, config["za-hub"]["db_uri"], source_hosts_queues)
    process.start()
    processes.append(process)

    process = processing.SourceMergerProcess("source-merger", stop_event, config["za-hub"]["db_uri"])
    process.start()
    processes.append(process)

    process = processing.ZabbixHostUpdater("zabbix-host-updater", stop_event, config["za-hub"]["zabbix_map_dir"], config["za-hub"]["db_uri"], config["za-hub"]["zabbix_url"], config["za-hub"]["zabbix_username"], config["za-hub"]["zabbix_password"], dryrun)
    process.start()
    processes.append(process)

    process = processing.ZabbixHostgroupUpdater("zabbix-hostgroup-updater", stop_event, config["za-hub"]["zabbix_map_dir"], config["za-hub"]["db_uri"], config["za-hub"]["zabbix_url"], config["za-hub"]["zabbix_username"], config["za-hub"]["zabbix_password"], dryrun)
    process.start()
    processes.append(process)

    process = processing.ZabbixTemplateUpdater("zabbix-template-updater", stop_event, config["za-hub"]["zabbix_map_dir"], config["za-hub"]["db_uri"], config["za-hub"]["zabbix_url"], config["za-hub"]["zabbix_username"], config["za-hub"]["zabbix_password"], dryrun)
    process.start()
    processes.append(process)

    with processing.ProcessTerminator(stop_event):
        status_interval = 60
        next_status = datetime.datetime.now()

        while not stop_event.is_set():
            if next_status < datetime.datetime.now():
                process_statuses = []

                for process in processes:
                    process_name = process.name
                    process_status = "alive" if process.is_alive() else "dead"
                    process_statuses.append(f"{process_name} is {process_status}")
                logging.info(f"Process status: {', '.join(process_statuses)}")

                next_status = datetime.datetime.now() + datetime.timedelta(seconds=status_interval)

            dead_process_names = [process.name for process in processes if not process.is_alive()]
            if dead_process_names:
                logging.error(f"A child has died: {', '.join(dead_process_names)}. Exiting")
                stop_event.set()

            time.sleep(1)

        for process in processes:
            logging.debug("Queues: {}".format(", ".join([str(queue.qsize()) for queue in source_hosts_queues])))
            logging.info(f"Waiting for: {process.name}({process.pid})")
            process.join()

    logging.info("Main exit")
