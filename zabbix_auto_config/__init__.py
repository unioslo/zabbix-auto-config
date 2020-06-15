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
    source_collector_dir = config["zac"]["source_collector_dir"]
    sys.path.append(source_collector_dir)

    section_prefix = "source-collector-"
    source_collector_sections = [config_section for config_section in config.sections() if config_section.startswith(section_prefix)]

    source_collectors = []

    for source_collector_section in source_collector_sections:
        source_collector_name = source_collector_section[len(section_prefix):]
        source_collector_module_name = config[source_collector_section]["module_name"]

        try:
            module = importlib.import_module(source_collector_module_name)
        except ModuleNotFoundError:
            logging.error("Unable to find source collector named '%s' in '%s'", source_collector_module_name, source_collector_dir)
            continue

        source_collector = {
            "name": source_collector_name,
            "module": module,
            "config": dict(config[source_collector_section])
        }

        source_collectors.append(source_collector)

    return source_collectors


def get_config():
    cwd = os.getcwd()
    config_file = os.path.join(cwd, "config.ini")
    config = configparser.ConfigParser()
    config.read(config_file)

    return config


def log_process_status(processes):
    process_statuses = []

    for process in processes:
        process_name = process.name
        process_status = "alive" if process.is_alive() else "dead"
        process_statuses.append(f"{process_name} is {process_status}")

    logging.debug("Process status: %s", ', '.join(process_statuses))


def main():
    config = get_config()

    logging.basicConfig(format='%(asctime)s %(levelname)s [%(processName)s %(process)d] [%(name)s] %(message)s', datefmt="%Y-%m-%dT%H:%M:%S%z", level=logging.DEBUG)
    multiprocessing_logging.install_mp_handler()
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    zabbix_config = dict(config["zabbix"])
    zabbix_config["failsafe"] = int(zabbix_config.get("failsafe", "20"))
    if zabbix_config["dryrun"] == "false":
        zabbix_config["dryrun"] = False
    elif zabbix_config["dryrun"] == "true":
        zabbix_config["dryrun"] = True
    else:
        raise Exception()

    logging.info("Main start (%d) version %s", os.getpid(), __version__)

    stop_event = multiprocessing.Event()
    processes = []

    source_hosts_queues = []
    source_collectors = get_source_collectors(config)
    for source_collector in source_collectors:
        source_hosts_queue = multiprocessing.Queue()
        process = processing.SourceCollectorProcess(source_collector["name"], source_collector["module"], source_collector["config"], source_hosts_queue)
        source_hosts_queues.append(source_hosts_queue)
        processes.append(process)
        process.start()

    process = processing.SourceHandlerProcess("source-handler", config["zac"]["db_uri"], source_hosts_queues)
    process.start()
    processes.append(process)

    process = processing.SourceMergerProcess("source-merger", config["zac"]["db_uri"], config["zac"]["host_modifier_dir"])
    process.start()
    processes.append(process)

    process = processing.ZabbixHostUpdater("zabbix-host-updater", config["zac"]["db_uri"], zabbix_config)
    process.start()
    processes.append(process)

    process = processing.ZabbixHostgroupUpdater("zabbix-hostgroup-updater", config["zac"]["db_uri"], zabbix_config)
    process.start()
    processes.append(process)

    process = processing.ZabbixTemplateUpdater("zabbix-template-updater", config["zac"]["db_uri"], zabbix_config)
    process.start()
    processes.append(process)

    with processing.SignalHandler(stop_event):
        status_interval = 60
        next_status = datetime.datetime.now()

        while not stop_event.is_set():
            if next_status < datetime.datetime.now():
                log_process_status(processes)
                next_status = datetime.datetime.now() + datetime.timedelta(seconds=status_interval)

            dead_process_names = [process.name for process in processes if not process.is_alive()]
            if dead_process_names:
                logging.error("A child has died: %s. Exiting", ', '.join(dead_process_names))
                stop_event.set()

            time.sleep(1)

        logging.debug("Queues: %s", ", ".join([str(queue.qsize()) for queue in source_hosts_queues]))

        for process in processes:
            logging.info("Terminating: %s(%d)", process.name, process.pid)
            process.terminate()

        alive_processes = [process for process in processes if process.is_alive()]
        while alive_processes:
            process = alive_processes[0]
            logging.info("Waiting for: %s(%d)", process.name, process.pid)
            log_process_status(processes)  # TODO: Too verbose?
            process.join(10)
            if process.exitcode is None:
                logging.warning("Process hanging. Signaling new terminate: %s(%d)", process.name, process.pid)
                process.terminate()
            time.sleep(1)
            alive_processes = [process for process in processes if process.is_alive()]

    logging.info("Main exit")
