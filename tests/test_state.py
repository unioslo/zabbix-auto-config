from __future__ import annotations

import datetime
import time

import pytest
from inline_snapshot import snapshot

from zabbix_auto_config.exceptions import ZACException
from zabbix_auto_config.processing import BaseProcess
from zabbix_auto_config.state import State
from zabbix_auto_config.state import StateProxy
from zabbix_auto_config.state import get_manager


def test_manager_state():
    manager = get_manager()
    state = manager.State()
    assert isinstance(state, StateProxy)
    # Test defaults
    assert state.ok is True
    assert state.error is None
    assert state.error_type is None
    assert state.error_count == 0
    assert state.error_time is None


@pytest.mark.parametrize("use_manager", [True, False])
@pytest.mark.parametrize("with_error", [True, False])
def test_state_set_ok(use_manager: bool, with_error: bool):
    if use_manager:
        state = get_manager().State()
    else:
        state = State()

    # Give state object some error state values
    if with_error:
        state.error = "Error"
        state.error_type = "ErrorType"
        state.error_count = 1
        state.error_time = datetime.datetime(2021, 1, 1, 0, 0, 0).timestamp()

    state.set_ok()
    assert state.ok is True
    assert state.error is None
    assert state.error_type is None
    assert state.error_time is None
    if with_error:
        assert state.error_count == 1
    else:
        assert state.error_count == 0


# Use a subclass of Exception so that we can test that
# the error type is set correctly
# Also needs to be in the global scope to be pickleable
class TimeoutError(Exception):
    pass


@pytest.mark.parametrize("use_manager", [True, False])
def test_state_set_error(use_manager: bool):
    if use_manager:
        state = get_manager().State()
    else:
        state = State()

    # Sanity test of defaults
    assert state.ok is True
    assert state.error is None
    assert state.error_type is None
    assert state.error_time is None
    assert state.error_count == 0

    time.sleep(0.01)  # to ensure later timestamps are greater
    e = TimeoutError("Test error")
    state.set_error(e)
    assert state.ok is False
    assert state.error == "Test error"
    assert state.error_type == "TimeoutError"
    assert state.error_time < time.time()
    assert state.error_count == 1

    # Set the error again to check count and time are updated
    prev_time = float(state.error_time)
    state.set_error(e)
    assert state.error_count == 2
    assert state.error_time > prev_time


class ZACExceptionProcess(BaseProcess):
    def work(self) -> None:
        raise ZACException("Test error")


@pytest.mark.timeout(10)
def test_state_in_other_process() -> None:
    state = get_manager().State()
    process = ZACExceptionProcess(
        name="test",
        state=state,
    )

    process.start()
    try:
        while process.state.ok:
            time.sleep(0.01)
        process.stop_event.set()
    finally:
        # stop process to prevent errors from accumulating
        process.join(timeout=0.01)

    assert process.state.ok is False
    assert process.state.error_type == "ZACException"
    assert process.state.error_count == 1
    assert process.state is state

    # Test that multiple state proxies do not refer to the same
    # underlying State object
    state2 = get_manager().State()
    assert state2.ok is True
    assert state2 is not state
    # This process will not fail and thus will set its state to OK
    process2 = BaseProcess(
        name="test",
        state=state2,
    )

    # Start and stop process, then check state
    try:
        process2.start()
        process2.stop_event.set()
    finally:
        process2.join(timeout=1)
    assert process2.state.ok is True
    assert process2.state.asdict() == state2.asdict()
    assert process2.state.asdict() != process.state.asdict()
    assert process2.state is not process.state


@pytest.mark.parametrize("use_manager", [True, False])
def test_state_asdict_ok(use_manager: bool) -> None:
    if use_manager:
        state = get_manager().State()
    else:
        state = State()
    state.set_ok()
    assert state.asdict() == snapshot(
        {
            "ok": True,
            "error": None,
            "error_type": None,
            "error_time": None,
            "error_count": 0,
            "execution_count": 0,
            "total_duration": datetime.timedelta(0),
            "max_duration": datetime.timedelta(0),
            "last_duration_warning": None,
        }
    )


class CustomException(Exception):
    pass


@pytest.mark.parametrize("use_manager", [True, False])
def test_state_asdict_error(use_manager: bool) -> None:
    if use_manager:
        state = get_manager().State()
    else:
        state = State()

    # Mocking datetime in subprocesses is a bit of a chore, so we just
    # check that the error_time is a timestamp value within a given range
    pre = time.time()
    state.set_error(CustomException("Test error"))
    post = time.time()
    d = state.asdict()

    assert post >= d["error_time"] >= pre
    d.pop("error_time")

    assert d == snapshot(
        {
            "ok": False,
            "error": "Test error",
            "error_type": "CustomException",
            "error_count": 1,
            "execution_count": 0,
            "total_duration": datetime.timedelta(0),
            "max_duration": datetime.timedelta(0),
            "last_duration_warning": None,
        }
    )


def test_state_record_execution() -> None:
    state = State()

    # Add 1 second execution
    state.record_execution(datetime.timedelta(seconds=1))
    assert state.execution_count == 1
    assert state.total_duration == datetime.timedelta(seconds=1)
    assert state.max_duration == datetime.timedelta(seconds=1)
    assert state.avg_duration == datetime.timedelta(seconds=1 / 1)

    # Add 2 second execution
    state.record_execution(datetime.timedelta(seconds=2))
    assert state.execution_count == 2
    assert state.total_duration == datetime.timedelta(seconds=3)
    assert state.max_duration == datetime.timedelta(seconds=2)
    assert state.avg_duration == datetime.timedelta(seconds=3 / 2)

    # Add 1 second execution
    state.record_execution(datetime.timedelta(seconds=1))
    assert state.execution_count == 3
    assert state.total_duration == datetime.timedelta(seconds=4)
    assert state.max_duration == datetime.timedelta(seconds=2)
    assert state.avg_duration == datetime.timedelta(seconds=4 / 3)
