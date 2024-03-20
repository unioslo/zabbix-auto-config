from __future__ import annotations


def modify(host):
    if host.hostname == "bar.example.com":
        host.properties.add("barry")
    return host
