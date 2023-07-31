import datetime
import importlib
import importlib.metadata
import json
import logging
import multiprocessing
import os
import os.path
import sys
import time
from typing import List

import multiprocessing_logging
import tomli

from . import exceptions
from . import models
from . import processing
from ._types import SourceCollectorDict, SourceCollectorModule


__version__ = importlib.metadata.version(os.path.basename(os.path.dirname(__file__)))


def get_source_collectors(config: models.Settings) -> List[SourceCollectorDict]:
    source_collector_dir = config.zac.source_collector_dir
    sys.path.append(source_collector_dir)

    source_collectors = []  # type: List[SourceCollectorDict]
    for (
        source_collector_name,
        source_collector_config,
    ) in config.source_collectors.items():
        try:
            module = importlib.import_module(source_collector_config.module_name)
        except ModuleNotFoundError:
            logging.error("Unable to find source collector named '%s' in '%s'", source_collector_config.module_name, source_collector_dir)
            continue

        if not isinstance(module, SourceCollectorModule):
            logging.error(
                "Source collector named '%s' is not a valid source collector module",
                source_collector_config.module_name,
            )
            continue

        source_collector = {
            "name": source_collector_name,
            "module": module,
            "config": source_collector_config,
        }  # type: SourceCollectorDict

        source_collectors.append(source_collector)

    return source_collectors


def get_config():
    cwd = os.getcwd()
    config_file = os.path.join(cwd, "config.toml")
    with open(config_file) as f:
        content = f.read()

    config = tomli.loads(content)
    config = models.Settings(**config)

    return config


def write_health(health_file, processes, queues, failsafe):
    now = datetime.datetime.now()
    health = {
        "date": now.isoformat(timespec="seconds"),
        "date_unixtime": int(now.timestamp()),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "all_ok": True,
        "processes": [],
        "queues": [],
        "failsafe": failsafe,
    }

    for process in processes:
        health["processes"].append({
            "name": process.name,
            "pid": process.pid,
            "alive": process.is_alive(),
            "ok": process.state.get("ok")
        })

    health["all_ok"] = all([p["ok"] for p in health["processes"]])

    for queue in queues:
        health["queues"].append({
            "size": queue.qsize(),
        })

    try:
        with open(health_file, "w") as f:
            f.write(json.dumps(health))
    except:
        logging.error("Unable to write health file: %s", health_file)


def log_process_status(processes):
    process_statuses = []

    for process in processes:
        process_name = process.name
        process_status = "alive" if process.is_alive() else "dead"
        process_statuses.append(f"{process_name} is {process_status}")

    logging.debug("Process status: %s", ', '.join(process_statuses))


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s [%(processName)s %(process)d] [%(name)s] %(message)s', datefmt="%Y-%m-%dT%H:%M:%S%z", level=logging.DEBUG)
    config = get_config()

    multiprocessing_logging.install_mp_handler()
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    logging.info("Main start (%d) version %s", os.getpid(), __version__)

    stop_event = multiprocessing.Event()
    state_manager = multiprocessing.Manager()
    processes = []

    source_hosts_queues = []
    source_collectors = get_source_collectors(config)
    for source_collector in source_collectors:
        source_hosts_queue = multiprocessing.Queue(maxsize=1)
        process = processing.SourceCollectorProcess(source_collector["name"], state_manager.dict(), source_collector["module"], source_collector["config"], source_hosts_queue)
        source_hosts_queues.append(source_hosts_queue)
        processes.append(process)

    try:
        process = processing.SourceHandlerProcess("source-handler", state_manager.dict(), config.zac.db_uri, source_hosts_queues)
        processes.append(process)

        process = processing.SourceMergerProcess("source-merger", state_manager.dict(), config.zac.db_uri, config.zac.host_modifier_dir)
        processes.append(process)

        process = processing.ZabbixHostUpdater("zabbix-host-updater", state_manager.dict(), config.zac.db_uri, config.zabbix)
        processes.append(process)

        process = processing.ZabbixHostgroupUpdater("zabbix-hostgroup-updater", state_manager.dict(), config.zac.db_uri, config.zabbix)
        processes.append(process)

        process = processing.ZabbixTemplateUpdater("zabbix-template-updater", state_manager.dict(), config.zac.db_uri, config.zabbix)
        processes.append(process)
    except exceptions.ZACException as e:
        logging.error("Failed to initialize child processes. Exiting: %s", str(e))
        sys.exit(1)

    for process in processes:
        process.start()

    with processing.SignalHandler(stop_event):
        status_interval = 60
        next_status = datetime.datetime.now()

        while not stop_event.is_set():
            if next_status < datetime.datetime.now():
                if config.zac.health_file is not None:
                    write_health(
                        config.zac.health_file,
                        processes,
                        source_hosts_queues,
                        config.zabbix.failsafe,
                    )
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
