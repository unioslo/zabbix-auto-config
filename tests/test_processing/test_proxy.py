from __future__ import annotations

from inline_snapshot import snapshot
from zabbix_auto_config.processing import ProxySyncAction


def test_proxy_sync_action_order() -> None:
    assert (
        ProxySyncAction.NOT_ELIGIBLE
        < ProxySyncAction.NO_MATCH
        < ProxySyncAction.CLEARED
        < ProxySyncAction.ASSIGNED
        < ProxySyncAction.UPDATED
        < ProxySyncAction.KEEP
    )


def test_proxy_sync_action_order_snapshot() -> None:
    assert list(ProxySyncAction) == snapshot(
        [
            ProxySyncAction.NOT_ELIGIBLE,
            ProxySyncAction.NO_MATCH,
            ProxySyncAction.CLEARED,
            ProxySyncAction.ASSIGNED,
            ProxySyncAction.UPDATED,
            ProxySyncAction.KEEP,
        ]
    )


def test_proxy_sync_action_is_unresolved() -> None:
    """Test that actions that don't keep or assign a proxy are identified as unresolved."""
    # UNRESOLVED:
    # These actions signal that host is not assigned a proxy or is not eligible for proxy assignment.
    assert ProxySyncAction.NOT_ELIGIBLE.is_unresolved() is True
    assert ProxySyncAction.NO_MATCH.is_unresolved() is True
    assert ProxySyncAction.CLEARED.is_unresolved() is True

    # RESOLVED:
    # These actions maintain or assign a proxy, so they are considered resolved.
    assert ProxySyncAction.ASSIGNED.is_unresolved() is False
    assert ProxySyncAction.UPDATED.is_unresolved() is False
    assert ProxySyncAction.KEEP.is_unresolved() is False
