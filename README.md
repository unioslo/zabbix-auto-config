# About

Zabbix-auto-config is an utility that aims to automatically configure hosts, host groups, host inventories and templates in the monitoring software [Zabbix](https://www.zabbix.com/).

Note: This is only tested with Zabbix 5.0 LTS.

# Quick start

This is a crash course in how to quickly get this application up and running in a local test environment:

## Zabbix test instance

Setup a Zabbix test instance with [podman](https://podman.io/) and [podman-compose](https://github.com/containers/podman-compose/).

```bash
TAG=alpine-5.0-latest ZABBIX_PASSWORD=secret podman-compose up -d
```

## Zabbix prerequisites

It is currently assumed that you have the following hostgroups in Zabbix. You should logon to Zabbix and create them:

* All-auto-disabled-hosts
* All-hosts

For automatic linking in templates you could create the templates:

* Template-barry
* Template-pizza

## Database

```bash
PGPASSWORD=secret psql -h localhost -U postgres -p 5432 -U zabbix << EOF
CREATE DATABASE zac;
\c zac
CREATE TABLE hosts (
    data jsonb
);
CREATE TABLE hosts_source (
    data jsonb
);
EOF
```

## Application

```bash
python3 -m venv venv
. venv/bin/activate
pip install -e .
cp config.sample.toml config.toml
sed -i 's/^dryrun = true$/dryrun = false/g' config.toml
mkdir -p path/to/source_collector_dir/ path/to/host_modifier_dir/ path/to/map_dir/
cat > path/to/source_collector_dir/mysource.py << EOF
from typing import Any, List
from zabbix_auto_config.models import Host

HOSTS = [
    {
        "hostname": "foo.example.com",
    },
    {
        "hostname": "bar.example.com",
    },
]


def collect(*args: Any, **kwargs: Any) -> List[Host]:
    hosts = []
    for host in HOSTS:
        host["enabled"] = True
        host["siteadmins"] = ["bob@example.com"]
        host["properties"] = ["pizza"]
        source = kwargs.get("source")
        if source:
            host["properties"].append(source)
        hosts.append(Host(**host))

    return hosts


if __name__ == "__main__":
    for host in collect():
        print(host.json())
EOF
cat > path/to/host_modifier_dir/mod.py << EOF
from zabbix_auto_config.models import Host

def modify(host: Host) -> Host:
    if host.hostname == "bar.example.com":
        host.properties.add("barry")
    return host
EOF
cat > path/to/map_dir/property_template_map.txt << EOF
pizza:Template-pizza
barry:Template-barry
EOF
cat > path/to/map_dir/property_hostgroup_map.txt << EOF
other:Hostgroup-other-hosts
EOF
cat > path/to/map_dir/siteadmin_hostgroup_map.txt << EOF
bob@example.com:Hostgroup-bob-hosts
EOF
```

Run the application:

```bash
zac
```

## Systemd unit

You could run this as a systemd service:

```ini
[Unit]
Description=Zabbix auto config
After=network.target

[Service]
User=zabbix
Group=zabbix
WorkingDirectory=/home/zabbix/zabbix-auto-config
Environment=PATH=/home/zabbix/zabbix-auto-config/venv/bin
ExecStart=/home/zabbix/zabbix-auto-config/venv/bin/zac
TimeoutSec=300

[Install]
WantedBy=multi-user.target
```

## Source collectors

As outlined in the [Application](#application) section, source collectors are Python modules (files) that are placed in a directory defined by the option `source_collector_dir` in the `[zac]` table of the config file. Zabbix-auto-config will attempt to load all modules in the directory that are referenced in the configuration file by name. Modules that are referenced in the config but not found in the directory will be ignored.

A source collector is a module that contains a function named `collect` that returns a list of `Host` objects. Zabbix-auto-config uses these host objects to create/update hosts in Zabbix.

A module that collects hosts from a file could look like this:

```python
# path/to/source_collector_dir/load_from_json.py

from typing import Any, Dict, List
from zabbix_auto_config.models import Host

DEFAULT_FILE = "hosts.json" 

def collect(*args: Any, **kwargs: Any) -> List[Host]:
    filename = kwargs.get("filename", DEFAULT_FILE)
    with open(filename, "r") as f:
        return [Host(**host) for host in f.read()]
```

Any module that contains a function named `collect` which takes a an arbitrary number of arguments and keyword arguments and returns a list of `Host` objects is recognized as a source collector module. Type annotations are optional, but recommended.

The corresponding config entry to load the `load_from_json.py` module above could look like this:

```toml
[source_collectors.load_from_json]
module_name = "load_from_json"
update_interval = 60
filename = "hosts.json"
```

The `module_name` and `update_interval` options are required for all source collector modules. Any other options are passed as keyword arguments to the `collect` function.

## Host modifiers

Host modifiers are Python modules (files) that are placed in a directory defined by the option `host_modifier_dir` in the `[zac]` table of the config file. A host modifier is a module that contains a function named `modify` that takes a `Host` object as its only argument, modifies it, and returns it. Zabbix-auto-config will attempt to load all modules in the given directory.

A host modifier module that adds a given siteadmin to all hosts could look like this:

```py
# path/to/host_modifier_dir/add_siteadmin.py

from zabbix_auto_config.models import Host

SITEADMIN = "admin@example.com"

def modify(host: Host) -> Host:
    host.siteadmins.add(SITEADMIN)
    return host
```

Any module that contains a function named `modify` which takes a `Host` and returns a `Host` is recognized as a host modifier module. Type annotations are optional, but recommended.

See the [`Host`](https://github.com/unioslo/zabbix-auto-config/blob/2b45f1cb7da0d46b8b218005ebbf751cb17f8793/zabbix_auto_config/models.py#L111-L123) class in `zabbix_auto_config/models.py` for the available fields that can be accessed and modified. One restriction applies: the `modify` function should _never_ modify the hostname of the host. Attempting to do so will result in an error. 

## Host inventory

Zac manages only inventory properties configured as `managed_inventory` in `config.toml`. An inventory property will not be removed/blanked from Zabbix even if the inventory property is removed from `managed_inventory` list or from the host in the source e.g:

1. Add "location=x" to a host in a source and wait for sync
2. Remove the "location" property from the host in the source
3. "location=x" will remain in Zabbix

