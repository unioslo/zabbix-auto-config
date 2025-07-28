from __future__ import annotations

import datetime
import importlib
import logging
import multiprocessing
import os
import sys
import time
from multiprocessing import Queue
from pathlib import Path
from typing import Optional

import multiprocessing_logging
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
from zabbix_auto_config.state import get_manager

app = typer.Typer(add_completion=False, pretty_exceptions_enable=False)


logger = structlog.stdlib.get_logger(__name__)


def get_source_collectors(config: models.Settings) -> list[SourceCollector]:
    source_collector_dir = config.zac.source_collector_dir
    sys.path.append(source_collector_dir)

    source_collectors: list[SourceCollector] = []
    for (
        source_collector_name,
        source_collector_config,
    ) in config.source_collectors.items():
        try:
            module = importlib.import_module(source_collector_config.module_name)
        except ModuleNotFoundError:
            logger.error(
                "Unable to find source collector named '%s' in '%s'",
                source_collector_config.module_name,
                source_collector_dir,
            )
            continue
        if not isinstance(module, SourceCollectorModule):
            logger.error(
                "Source collector named '%s' is not a valid source collector module",
                source_collector_config.module_name,
            )
            continue
        source_collectors.append(
            SourceCollector(
                name=source_collector_name,
                module=module,
                config=source_collector_config,
            )
        )
    return source_collectors


def get_host_modifiers(modifier_dir: str) -> list[HostModifier]:
    sys.path.append(modifier_dir)
    try:
        module_names = [
            filename[:-3]
            for filename in os.listdir(modifier_dir)
            if filename.endswith(".py") and filename != "__init__.py"
        ]
    except FileNotFoundError:
        logger.error("Host modifier directory %s does not exist.", modifier_dir)
        sys.exit(1)
    host_modifiers: list[HostModifier] = []
    for module_name in module_names:
        module = importlib.import_module(module_name)
        if not isinstance(module, HostModifierModule):
            logger.warning(
                "Module '%s' is not a valid host modifier module. Skipping.",
                module_name,
            )
            continue
        host_modifiers.append(
            HostModifier(
                name=module_name,
                module=module,
            )
        )
    logger.info(
        "Loaded %d host modifiers: %s",
        len(host_modifiers),
        ", ".join([repr(modifier.name) for modifier in host_modifiers]),
    )
    return host_modifiers


def log_process_status(processes: list[processing.BaseProcess]) -> None:
    process_statuses = []

    for process in processes:
        process_name = process.name
        process_status = "alive" if process.is_alive() else "dead"
        process_statuses.append(f"{process_name} is {process_status}")

    logger.info("Process status: %s", ", ".join(process_statuses))


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
    multiprocessing_logging.install_mp_handler()

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.CallsiteParameterAdder(
                parameters=[structlog.processors.CallsiteParameter.PROCESS_NAME]
            ),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    # Configure stdlib logging to work with structlog
    logging.basicConfig(
        format="%(message)s",
        level=logging.DEBUG,
    )
    config = get_config(config_path)

    if failsafe is not None:
        config.zabbix.failsafe = failsafe
    if dryrun is not None:
        config.zabbix.dryrun = dryrun

    logging.getLogger().setLevel(config.zac.log_level)
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.ERROR)

    logger.info("Main start (%d) version %s", os.getpid(), __version__)
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
        except Exception as e:
            logger.error("Unable to start process %s: %s", pr.name, e)
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
                    "A child has died: %s. Exiting", ", ".join(dead_process_names)
                )
                stop_event.set()

            time.sleep(1)

        logger.info(
            "Queues: %s",
            ", ".join([str(queue.qsize()) for queue in source_hosts_queues]),
        )

        for pr in processes:
            logger.info("Terminating: %s(%d)", pr.name, pr.pid)
            pr.terminate()

        def get_alive():
            return [process for process in processes if process.is_alive()]

        while alive := get_alive():
            log_process_status(processes)
            for process in alive:
                logger.info("Waiting for: %s(%d)", process.name, process.pid)
                process.join(10)
                if process.exitcode is None:
                    logger.warning(
                        "Process hanging. Signaling new terminate: %s(%d)",
                        process.name,
                        process.pid,
                    )
                    process.terminate()
            time.sleep(1)

    logger.info("Main exit")


def run() -> None:
    app()


if __name__ == "__main__":
    run()
