import pytest
from pydantic import ValidationError
from zabbix_auto_config import models


# NOTE: Do not test msg and ctx of Pydantic errors!
# They are not guaranteed to be stable between minor versions.
# https://docs.pydantic.dev/latest/version-compatibility/#pydantic-v2-changes


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
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("proxy_pattern",)
    assert "Must be valid regexp pattern: '['" in error["msg"]
    assert error["type"] == "assertion_error"


def test_invalid_interface(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-interface")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("interfaces", 0)
    assert "Interface of type 2 must have details set" in error["msg"]
    assert error["type"] == "value_error"


def test_duplicate_interface(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "duplicate-interface")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("interfaces",)
    assert "No duplicate interface types: [1, 1]" in error["msg"]
    assert error["type"] == "assertion_error"



def test_invalid_importance(invalid_hosts):
    host = find_host_by_hostname(invalid_hosts, "invalid-importance")
    with pytest.raises(ValidationError) as exc_info:
        models.Host(**host)
    errors = exc_info.value.errors()
    assert len(errors) == 1
    error = errors[0]
    assert error["loc"] == ("importance",)
    assert error["input"] == -1
    assert error["type"] == "greater_than_equal"



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
