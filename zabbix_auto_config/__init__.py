from __future__ import annotations

import datetime
import importlib
import multiprocessing
import os
import sys
import time
from multiprocessing import Queue
from pathlib import Path
from typing import Literal
from typing import Optional
from typing import TypedDict

import structlog
import typer

from zabbix_auto_config import models
from zabbix_auto_config import processing
from zabbix_auto_config.__about__ import __version__
from zabbix_auto_config._types import HostModifier
from zabbix_auto_config._types import HostModifierModule
from zabbix_auto_config._types import SourceCollector
from zabbix_auto_config._types import SourceCollectorModule
from zabbix_auto_config.config import get_config
from zabbix_auto_config.db import init_db
from zabbix_auto_config.health import write_health
from zabbix_auto_config.log import configure_logging
from zabbix_auto_config.state import get_manager

app = typer.Typer(add_completion=False, pretty_exceptions_enable=False)


logger = structlog.stdlib.get_logger(__name__)


def get_source_collectors(config: models.Settings) -> list[SourceCollector]:
    source_collector_dir = config.zac.source_collector_dir
    sys.path.append(source_collector_dir)

    log = logger.bind(source_collector_dir=source_collector_dir)

    source_collectors: list[SourceCollector] = []
    for (
        source_collector_name,
        source_collector_config,
    ) in config.source_collectors.items():
        log_mod = log.bind(source_collector=source_collector_config.module_name)
        try:
            log_mod.debug("Importing source collector module")
            module = importlib.import_module(source_collector_config.module_name)
        except ModuleNotFoundError:
            log_mod.error("Unable to find source collector module")
            continue
        except Exception:
            log_mod.exception("Error importing source collector module")
            continue

        if not isinstance(module, SourceCollectorModule):
            log_mod.error("Source collector is not a valid source collector module")
            continue

        source_collectors.append(
            SourceCollector(
                name=source_collector_name,
                module=module,
                config=source_collector_config,
            )
        )
    log.info(
        "Loaded source collectors", collectors=[sc.name for sc in source_collectors]
    )
    return source_collectors


def get_host_modifiers(modifier_dir: str) -> list[HostModifier]:
    sys.path.append(modifier_dir)
    log = logger.bind(modifier_dir=modifier_dir)

    # Gather names of modules to import
    try:
        module_names = [
            filename[:-3]
            for filename in os.listdir(modifier_dir)
            if filename.endswith(".py") and filename != "__init__.py"
        ]
    except FileNotFoundError:
        log.error("Host modifier directory does not exist")
        sys.exit(1)

    # Import each module and check if it is a valid HostModifierModule
    host_modifiers: list[HostModifier] = []
    for module_name in module_names:
        module = importlib.import_module(module_name)
        if not isinstance(module, HostModifierModule):
            logger.warning(
                "Module is not a valid host modifier module. Skipping",
                module=module_name,
            )
            continue
        host_modifiers.append(
            HostModifier(
                name=module_name,
                module=module,
            )
        )
    log.info(
        "Loaded host modifiers",
        modifiers=[modifier.name for modifier in host_modifiers],
    )
    return host_modifiers


def log_process_status(processes: list[processing.BaseProcess]) -> None:
    class ProcessStatus(TypedDict):
        name: str
        pid: int | None
        status: Literal["alive", "dead"]

    process_statuses: list[ProcessStatus] = []

    for process in processes:
        process_name = process.name
        process_status = "alive" if process.is_alive() else "dead"
        process_statuses.append(
            ProcessStatus(
                name=process_name,
                pid=process.pid,
                status=process_status,
            )
        )

    logger.info("Process status", status=process_statuses)


@app.command()
def main(
    failsafe: Optional[int] = typer.Option(  # noqa: B008
        None,
        "--failsafe",
        "-F",
        help="Maximum number of hosts to change.",
        show_default=False,
    ),
    dryrun: Optional[bool] = typer.Option(  # noqa: B008
        None,
        "--dryrun",
        "-D",
        help="Dry run mode.",
    ),
    config_path: Optional[Path] = typer.Option(  # noqa: B008
        None,
        "--config",
        "-C",
        help="Path to config file.",
        show_default=False,
    ),
) -> None:
    """Run Zabbix-auto-config."""
    logger.info("Main start", pid=os.getpid(), version=__version__)

    config = get_config(config_path)

    if failsafe is not None:
        config.zabbix.failsafe = failsafe
    if dryrun is not None:
        config.zabbix.dryrun = dryrun

    configure_logging(config)

    stop_event = multiprocessing.Event()
    state_manager = get_manager()

    # Ensure database and tables exist
    init_db(config)

    # Import host modifier and source collector modules
    host_modifiers = get_host_modifiers(config.zac.host_modifier_dir)
    source_collectors = get_source_collectors(config)

    # Initialize source collector processes from imported modules
    source_hosts_queues: list[Queue[models.Host]] = []
    src_processes: list[processing.BaseProcess] = []
    for source_collector in source_collectors:
        # Each source collector has its own queue
        source_hosts_queue: Queue[models.Host] = Queue(maxsize=1)
        source_hosts_queues.append(source_hosts_queue)
        process: processing.BaseProcess = processing.SourceCollectorProcess(
            source_collector.name,
            state_manager.State(),
            config,
            source_collector.module,
            source_collector.config,
            source_hosts_queue,
        )
        src_processes.append(process)

    # Initialize the default processes
    processes: list[processing.BaseProcess] = [
        processing.SourceHandlerProcess(
            "source-handler",
            state_manager.State(),
            config,
            source_hosts_queues,
        ),
        processing.SourceMergerProcess(
            "source-merger",
            state_manager.State(),
            config,
            host_modifiers,
        ),
        processing.ZabbixHostUpdater(
            "zabbix-host-updater",
            state_manager.State(),
            config,
        ),
        processing.ZabbixHostgroupUpdater(
            "zabbix-hostgroup-updater",
            state_manager.State(),
            config,
        ),
        processing.ZabbixTemplateUpdater(
            "zabbix-template-updater",
            state_manager.State(),
            config,
        ),
    ]

    # Garbage collection process
    if config.zac.process.garbage_collector.enabled:
        processes.append(
            processing.ZabbixGarbageCollector(
                "zabbix-garbage-collector",
                state_manager.State(),
                config,
            )
        )

    # Combine the source collector processes with the other processes
    processes.extend(src_processes)

    # Abort if we can't start _all_ processes
    for pr in processes:
        try:
            pr.start()
        except Exception:
            logger.exception("Unable to start process", name=pr.name)
            stop_event.set()  # Stop other processes immediately
            break

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
                next_status = datetime.datetime.now() + datetime.timedelta(
                    seconds=status_interval
                )

            dead_process_names = [
                process.name for process in processes if not process.is_alive()
            ]
            if dead_process_names:
                logger.error(
                    "A child has died. Exiting", dead_processes=[dead_process_names]
                )
                stop_event.set()

            time.sleep(1)

        for pr in processes:
            logger.info("Terminating process", name=pr.name, pid=pr.pid)
            pr.terminate()

        def get_alive():
            return [process for process in processes if process.is_alive()]

        while alive := get_alive():
            log_process_status(processes)
            for process in alive:
                log = logger.bind(
                    name=process.name,
                    pid=process.pid,
                )
                log.info("Waiting for process to exit")
                process.join(10)
                if process.exitcode is None:
                    log.warning("Process hanging. Signaling new terminate")
                    process.terminate()
            time.sleep(1)

    logger.info("Main exit")


def run() -> None:
    app()


if __name__ == "__main__":
    run()
