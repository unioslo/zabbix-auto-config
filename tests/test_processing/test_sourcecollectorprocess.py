from __future__ import annotations

import multiprocessing
import time

import pytest
from zabbix_auto_config.models import Host
from zabbix_auto_config.models import Settings
from zabbix_auto_config.models import SourceCollectorSettings
from zabbix_auto_config.processing import SourceCollectorProcess
from zabbix_auto_config.state import get_manager


class SourceCollector:
    @staticmethod
    def collect(*args, **kwargs) -> list[Host]:
        host = Host(
            hostname="foo.example.com",
            enabled=True,
        )
        return [host, host]


@pytest.mark.timeout(5)
def test_source_collector_process(config: Settings):
    process = SourceCollectorProcess(
        name="test-source",
        state=get_manager().State(),
        config=config,
        module=SourceCollector,
        settings=SourceCollectorSettings(
            module_name="source_collector",
            update_interval=1,
            disable_duration=2,
            exit_on_error=False,
            error_duration=10,
            error_tolerance=5,
        ),
        source_hosts_queue=multiprocessing.Queue(),
    )

    try:
        process.start()
        hosts = process.source_hosts_queue.get()
        assert len(hosts["hosts"]) == 2
        assert hosts["hosts"][0].hostname == "foo.example.com"
        assert process.state.ok is True
    finally:
        process.stop_event.set()
        process.join(timeout=0.01)


# NOTE: Has to be defined in the global scope to be pickleable by multiprocessing
class FaultySourceCollector:
    @staticmethod
    def collect(*args, **kwargs) -> list[Host]:
        raise Exception("Source collector error!!")


@pytest.mark.timeout(5)
def test_source_collector_disable_on_failure(config: Settings):
    process = SourceCollectorProcess(
        name="test-source",
        state=get_manager().State(),
        config=config,
        module=FaultySourceCollector,
        settings=SourceCollectorSettings(
            module_name="faulty_source_collector",
            update_interval=1,
            disable_duration=3600,
            exit_on_error=False,
            error_duration=10,
            error_tolerance=0,
        ),
        source_hosts_queue=multiprocessing.Queue(),
    )

    # Start process and wait until it fails
    try:
        process.start()
        while process.state.ok is True:
            time.sleep(0.01)
        assert process.state.ok is False
        assert process.source_hosts_queue.empty() is True
        process.stop_event.set()
    finally:
        process.join(timeout=0.01)
