import multiprocessing
import time
from typing import List

from zabbix_auto_config.processing import SourceCollectorProcess
from zabbix_auto_config.models import Host, SourceCollectorSettings


class SourceCollector:
    @staticmethod
    def collect(*args, **kwargs) -> List[Host]:
        host = Host(
            hostname="foo.example.com",
            enabled=True,
        )
        return [host, host]


class FaultySourceCollector:
    @staticmethod
    def collect(*args, **kwargs) -> List[Host]:
        raise Exception("Source collector error!!")


def test_source_collector_process():
    process = SourceCollectorProcess(
        name="test-source",
        state=multiprocessing.Manager().dict(),
        module=SourceCollector,
        config=SourceCollectorSettings(
            module_name="source_collector",
            update_interval=1,
            disable_duration=2,
            exit_on_error=False,
            error_interval=10,
            error_tolerance=5,
        ),
        source_hosts_queue=multiprocessing.Queue(),
    )

    process.start()

    # FIXME: this is potentially flaky!
    # We wait for the process to start up completely before we
    # set the stop event. In order to not have to rewrite the class,
    # we just wait for a bit. This is not ideal.
    # The alternative is passing in a an Event which is set when the class
    # enters run() for the first time. However, this would require a rewrite
    # of the class and all callers of it, so we'll just wait for now.
    time.sleep(0.5)  # wait for process to start
    process.stop_event.set()
    process.join(timeout=0.1)

    hosts = process.source_hosts_queue.get()
    assert len(hosts["hosts"]) == 2
    assert hosts["hosts"][0].hostname == "foo.example.com"
    assert process.state["ok"] is True


def test_source_collector_disable_on_failure():
    process = SourceCollectorProcess(
        name="test-source",
        state=multiprocessing.Manager().dict(),
        module=FaultySourceCollector,
        config=SourceCollectorSettings(
            module_name="faulty_source_collector",
            update_interval=0.1,
            disable_duration=3600,
            exit_on_error=False,
            error_interval=10,
            error_tolerance=0,
        ),
        source_hosts_queue=multiprocessing.Queue(),
    )
    # FIXME: potentially flaky test!
    # In addition to the problem described in the test above,
    # if we terminate the process before it has the chance to
    # set state["ok"] to False, the test will fail.
    process.start()
    time.sleep(0.5)  # wait for process to start
    process.stop_event.set()
    process.join(timeout=0.5)

    assert process.state["ok"] is False
    assert process.source_hosts_queue.empty() is True

    # TODO: assert that process is disabled.
    # We probably need to add disablement info to state dict
