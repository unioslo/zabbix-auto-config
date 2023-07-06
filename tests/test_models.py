import pytest
from pydantic.error_wrappers import ValidationError
from zabbix_auto_config import models


def find_host_by_hostname(hosts, hostname):
    for host in hosts:
        if host["hostname"].startswith(hostname):
            return host
    return None


def test_minimal_host(minimal_hosts):
    for host in minimal_hosts:
        models.Host(**host)


def test_full_host(full_hosts):
    for host in full_hosts:
        models.Host(**host)


def test_invalid_proxy_pattern(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-proxy-pattern")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    assert exc_info.value.errors() == [
        {
            "loc": ("proxy_pattern",),
            "msg": "Must be valid regexp pattern: '['",
            "type": "assertion_error",
        }
    ]


def test_invalid_interface(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-interface")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    assert exc_info.value.errors() == [
        {
            "loc": ("interfaces", 0, "type"),
            "msg": "Interface of type 2 must have details set",
            "type": "value_error",
        }
    ]


def test_duplicate_interface(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "duplicate-interface")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    assert exc_info.value.errors() == [
        {
            "loc": ("interfaces",),
            "msg": "No duplicate interface types: [1, 1]",
            "type": "assertion_error",
        }
    ]


def test_invalid_importance(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-importance")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    assert exc_info.value.errors() == [
        {
            "loc": ("importance",),
            "msg": "ensure this value is greater than or equal to 0",
            "type": "value_error.number.not_ge",
            "ctx": {"limit_value": 0},
        }
    ]



def test_host_merge(full_hosts):
    """Tests Host.merge()"""
    host = find_host_by_hostname(full_hosts, "foo")
    h1 = models.Host(**host)

    host["hostname"] = "bar.example.com"
    host["enabled"] = False
    host["properties"] = {"prop2", "prop3"}
    host["siteadmins"] = {"bob@example.com", "chuck@example.com"}
    host["sources"] = {"source2", "source3"}
    host["tags"] = [["tag2", "y"], ["tag3", "z"]]
    host["importance"] = 2
    # TODO: interfaces
    # TODO: proxy_pattern
    host["inventory"] = {"foo": "bar", "baz": "qux"}
    h2 = models.Host(**host)

    h1.merge(h2)

    assert h1.hostname == "foo.example.com"
    assert h1.enabled
    assert h1.properties == {"prop1", "prop2", "prop3"}
    assert h1.siteadmins == {
        "alice@example.com",
        "bob@example.com",
        "chuck@example.com",
    }
    assert h1.sources == {"source1", "source2", "source3"}
    assert h1.tags == {("tag1", "x"), ("tag2", "y"), ("tag3", "z")}
    assert h1.importance == 1
    assert h1.inventory == {"foo": "bar", "baz": "qux"}


def test_host_merge_invalid(full_hosts):
    """Tests Host.merge() with incorrect argument type"""
    host = find_host_by_hostname(full_hosts, "foo")
    h1 = models.Host(**host)
    with pytest.raises(TypeError):
        h1.merge(object())


def test_sourcecollectorsettings_no_tolerance() -> None:
    """Setting no error tolerance will cause the error_duration to be set
    to a non-zero value.

    Per note in the docstring of SourceCollectorSettings.error_duration,
    the value of error_duration is set to a non-zero value to ensure that
    the error is not discarded when calling RollingErrorCounter.check().
    """
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_tolerance=0,
        error_duration=0,
    )
    assert settings.error_tolerance == 0
    # In case the actual implementaiton changes in the future, we don't
    # want to test the _exact_ value, but we know it will not be 0
    assert settings.error_duration > 0


def test_sourcecollectorsettings_duration_too_short(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Setting the value of error_duration to a value that is less
    than the product of update_interval and error_tolerance will adjust
    the value of error_duration to be at least that value + 1 update interval."""
    settings = models.SourceCollectorSettings(
        module_name="foo",
        update_interval=60,
        error_tolerance=5,
        error_duration=60,
    )
    assert settings.error_tolerance == 5
    assert (
        settings.error_duration == 360
    )  # update_interval * error_tolerance + update_interval

    # A log message should have been generated telling the user about it
    assert len(caplog.records) == 1
    msg = caplog.records[0]
    assert msg.levelname == "WARNING"
    assert "foo" in msg.message
    assert "60" in msg.message
    assert "360" in msg.message
